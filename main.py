import os
import re
import json
import hashlib
import fnmatch
from pathlib import Path
from typing import Optional, List, Dict, Any, AsyncGenerator
from dataclasses import dataclass, field

from astrbot.api.event import filter, AstrMessageEvent, MessageEventResult
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
from astrbot.api.message_components import Plain
from astrbot.core.platform.astr_message_event import AstrMessageEvent
from astrbot.core.provider.entities import LLMResponse, ProviderRequest
from astrbot.core.message.message_event_result import MessageChain


@dataclass
class SecurityRule:
    """安全规则配置"""
    name: str
    description: str
    enabled: bool = True
    severity: str = "high"  # low, medium, high, critical
    action: str = "block"  # block, warn, log


@dataclass
class AegisConfig:
    """Aegis 插件配置"""
    enabled: bool = True
    model_provider: str = ""  # 用于分析的安全模型
    system_prompt: str = """
你是一个安全守护者，负责保护 AstrBot 和用户隐私安全。

你的职责：
1. 识别任何试图修改、删除 AstrBot 核心文件的行为
2. 识别任何试图通过代码执行危害系统的行为
3. 识别任何可能泄露用户隐私信息的输出
4. 只允许安装新插件和添加 skills 的操作

核心保护路径（禁止修改/删除）：
- astrbot/ 目录下的所有核心代码文件
- main.py, runtime_bootstrap.py 等入口文件
- .venv/ 虚拟环境
- data/ 目录下的配置文件（除 plugins/ 和 skills/ 外）

允许的操作：
- 安装新插件到 data/plugins/
- 添加新的 skills
- 正常的对话和查询

当检测到危险操作时，请回复：
{"action": "block", "reason": "具体原因", "suggestion": "替代方案"}

当检测安全时，请回复：
{"action": "allow", "reason": "安全"}
"""
    
    # 文件保护配置
    protected_paths: List[str] = field(default_factory=lambda: [
        "astrbot/**",
        "main.py",
        "runtime_bootstrap.py",
        "pyproject.toml",
        "requirements.txt",
        ".venv/**",
        "data/cmd_config.json",
        "data/*.db",
        "data/*.sqlite",
    ])
    
    # 允许修改的路径（白名单）
    allowed_paths: List[str] = field(default_factory=lambda: [
        "data/plugins/**",
        "data/skills/**",
        "data/knowledge_base/**",
        "data/temp/**",
    ])
    
    # 隐私信息模式
    privacy_patterns: Dict[str, str] = field(default_factory=lambda: {
        "api_key": r"[a-zA-Z0-9_-]{20,}",
        "password": r"password[\"'\s]*[=:][\"'\s]*[^\s]+",
        "token": r"token[\"'\s]*[=:][\"'\s]*[^\s]+",
        "secret": r"secret[\"'\s]*[=:][\"'\s]*[^\s]+",
        "phone": r"1[3-9]\d{9}",
        "email": r"[\w.-]+@[\w.-]+\.\w+",
        "id_card": r"\d{17}[\dXx]|\d{15}",
        "ip_address": r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    })
    
    # 危险命令模式
    dangerous_commands: List[str] = field(default_factory=lambda: [
        "rm -rf", "rm -r /", "rm -rf /",
        "del /f /s /q", "rmdir /s /q",
        "format", "fdisk", "mkfs",
        ":(){ :|:& };:",  # fork bomb
        "> /dev/sda", "> /dev/null",
        "dd if=/dev/zero",
        "mv /* /dev/null",
    ])
    
    # 通知配置
    notify_on_block: bool = True
    notify_message: str = "🛡️ Aegis 安全系统已阻止潜在危险操作，保护您的 AstrBot 安全。"


@register("aegis", "tangsenfei", "Aegis - AstrBot 安全守护者，保护核心文件和用户隐私", "1.0.0")
class AegisPlugin(Star):
    """
    Aegis - AstrBot 安全守护者插件
    
    功能：
    1. 阻止对 AstrBot 核心文件的修改和删除
    2. 阻止在聊天中输出敏感个人信息
    3. 只允许安装插件和添加 skills
    4. 向会话通知安全事件
    """
    
    def __init__(self, context: Context):
        super().__init__(context)
        self.config = self._load_config()
        self.project_root = Path(__file__).parent.parent.parent.parent
        self.blocked_operations: List[Dict] = []
        
    def _load_config(self) -> AegisConfig:
        """加载配置文件"""
        config_path = Path(__file__).parent / "config.json"
        if config_path.exists():
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return AegisConfig(**data)
            except Exception as e:
                logger.error(f"[Aegis] 加载配置失败: {e}")
        return AegisConfig()
    
    def _save_config(self):
        """保存配置文件"""
        config_path = Path(__file__).parent / "config.json"
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(self.config.__dict__, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"[Aegis] 保存配置失败: {e}")
    
    async def initialize(self):
        """插件初始化"""
        logger.info("[Aegis] 安全守护者已启动，正在保护您的 AstrBot...")
        self._save_config()
    
    def _is_path_protected(self, path: str) -> tuple[bool, str]:
        """
        检查路径是否受保护
        返回: (是否受保护, 匹配的规则)
        """
        # 标准化路径
        path = path.replace("\\", "/").strip("/")
        full_path = (self.project_root / path).resolve()
        
        # 检查是否在白名单中
        for allowed in self.config.allowed_paths:
            allowed_pattern = allowed.replace("**", "*")
            if fnmatch.fnmatch(path, allowed_pattern) or fnmatch.fnmatch(str(full_path), allowed_pattern):
                return False, ""
        
        # 检查是否在保护列表中
        for protected in self.config.protected_paths:
            protected_pattern = protected.replace("**", "*")
            if fnmatch.fnmatch(path, protected_pattern) or fnmatch.fnmatch(str(full_path), protected_pattern):
                return True, protected
            
            # 检查是否试图访问父目录
            try:
                protected_path = (self.project_root / protected.replace("**", "")).resolve()
                if str(full_path).startswith(str(protected_path)) and protected_path != self.project_root:
                    return True, protected
            except:
                pass
        
        return False, ""
    
    def _contains_dangerous_command(self, text: str) -> tuple[bool, str]:
        """检查是否包含危险命令"""
        text_lower = text.lower()
        for cmd in self.config.dangerous_commands:
            if cmd.lower() in text_lower:
                return True, cmd
        return False, ""
    
    def _detect_privacy_leak(self, text: str) -> tuple[bool, List[str]]:
        """
        检测是否包含隐私信息泄露
        返回: (是否泄露, [泄露类型列表])
        """
        leaks = []
        for leak_type, pattern in self.config.privacy_patterns.items():
            if re.search(pattern, text, re.IGNORECASE):
                leaks.append(leak_type)
        return len(leaks) > 0, leaks
    
    def _sanitize_privacy_info(self, text: str) -> str:
        """对隐私信息进行脱敏处理"""
        sanitized = text
        replacements = {
            "api_key": (r"[a-zA-Z0-9_-]{20,}", "***API_KEY_HIDDEN***"),
            "phone": (r"1[3-9]\d{9}", "***PHONE_HIDDEN***"),
            "email": (r"[\w.-]+@[\w.-]+\.\w+", "***EMAIL_HIDDEN***"),
            "id_card": (r"\d{17}[\dXx]|\d{15}", "***ID_CARD_HIDDEN***"),
        }
        
        for leak_type, (pattern, replacement) in replacements.items():
            sanitized = re.sub(pattern, replacement, sanitized)
        
        return sanitized
    
    async def _analyze_with_llm(self, content: str, context_type: str = "file_operation") -> Dict[str, Any]:
        """
        使用配置的 LLM 分析内容安全性
        """
        if not self.config.model_provider:
            # 如果没有配置模型，使用本地规则
            return {"action": "allow", "reason": "未配置安全模型，使用本地规则"}
        
        try:
            prompt = f"""
请分析以下操作的安全性：

操作类型: {context_type}
内容: {content}

请根据系统提示词的规则，判断是否应该阻止此操作。
只返回 JSON 格式，不要有任何其他内容。
"""
            
            response = await self.context.llm_generate(
                chat_provider_id=self.config.model_provider,
                prompt=prompt,
                system_prompt=self.config.system_prompt,
            )
            
            # 尝试解析 JSON 响应
            result_text = response.completion_text
            # 提取 JSON 部分
            json_match = re.search(r'\{[^}]+\}', result_text)
            if json_match:
                return json.loads(json_match.group())
            
            return {"action": "allow", "reason": "无法解析模型响应"}
            
        except Exception as e:
            logger.error(f"[Aegis] LLM 分析失败: {e}")
            return {"action": "allow", "reason": f"LLM 分析失败: {e}"}
    
    async def _notify_protection(self, event: AstrMessageEvent, action: str, reason: str, original_content: str = ""):
        """向会话发送安全通知"""
        if not self.config.notify_on_block:
            return
        
        message = f"""🛡️ **Aegis 安全警报**

⚠️ 检测到潜在风险操作，已被阻止！

📋 **操作类型**: {action}
🔒 **阻止原因**: {reason}
"""
        
        if original_content:
            # 对原始内容进行脱敏
            safe_content = self._sanitize_privacy_info(original_content[:200])
            message += f"\n📝 **相关内容**: {safe_content}..."
        
        message += "\n\n💡 提示：只允许安装插件和添加 skills，禁止修改核心文件。"
        
        # 发送通知 - 创建 MessageChain
        msg_chain = MessageChain()
        msg_chain.chain.append(Plain(message))
        await event.send(msg_chain)
        
        # 记录到日志
        logger.warning(f"[Aegis] 阻止操作: {action}, 原因: {reason}")
    
    # ============ 事件拦截器 ============
    
    @filter.on_decorating_result()
    async def on_decorating_result(self, event: AstrMessageEvent) -> None:
        """
        拦截并检查 LLM 输出结果
        阻止输出敏感信息
        """
        if not self.config.enabled:
            return
        
        try:
            result = event.get_result()
            if result is None:
                return
            
            # 获取结果中的文本内容
            result_text = ""
            chain = getattr(result, 'chain', [])
            if not chain:
                return
                
            for component in chain:
                text_attr = getattr(component, 'text', None)
                if text_attr is not None and isinstance(text_attr, str):
                    result_text += text_attr
            
            if not result_text:
                return
            
            # 检测隐私泄露
            has_leak, leak_types = self._detect_privacy_leak(result_text)
            
            if has_leak:
                logger.warning(f"[Aegis] 检测到隐私信息泄露: {leak_types}")
                
                # 对结果进行脱敏处理
                sanitized_text = self._sanitize_privacy_info(result_text)
                
                # 替换原始结果
                for component in chain:
                    text_attr = getattr(component, 'text', None)
                    if text_attr is not None and isinstance(text_attr, str):
                        setattr(component, 'text', sanitized_text)
                
                # 发送通知
                await self._notify_protection(
                    event, 
                    "隐私信息过滤", 
                    f"检测到敏感信息类型: {', '.join(leak_types)}",
                    result_text
                )
                
        except Exception as e:
            logger.error(f"[Aegis] 结果装饰器错误: {e}")
    
    @filter.on_llm_request()
    async def on_llm_request(self, event: AstrMessageEvent, req: ProviderRequest) -> None:
        """
        拦截 LLM 请求，检查是否包含危险操作
        """
        if not self.config.enabled:
            return
        
        try:
            # 检查提示词中的危险命令
            prompt_text = req.prompt or ""
            
            # 检查是否包含文件操作相关内容
            file_patterns = [
                r'(删除|remove|delete|rm)\s+.*(?:astrbot|核心|core)',
                r'(修改|编辑|edit|modify)\s+.*(?:astrbot|核心|core)',
                r'(覆盖|替换|overwrite|replace)\s+.*(?:astrbot|核心|core)',
            ]
            
            for pattern in file_patterns:
                if re.search(pattern, prompt_text, re.IGNORECASE):
                    logger.warning(f"[Aegis] 检测到危险文件操作请求")
                    
                    # 使用 LLM 进一步分析
                    analysis = await self._analyze_with_llm(prompt_text, "file_operation")
                    
                    if analysis.get("action") == "block":
                        await self._notify_protection(
                            event,
                            "危险文件操作",
                            analysis.get("reason", "试图修改核心文件"),
                            prompt_text
                        )
                        # 阻止请求
                        req.prompt = "用户请求已被安全系统阻止。请回复：'该操作涉及系统安全，已被阻止。如有需要，请使用合法的插件安装方式。'"
                        return
            
            # 检查危险命令
            has_danger, danger_cmd = self._contains_dangerous_command(prompt_text)
            if has_danger:
                logger.warning(f"[Aegis] 检测到危险命令: {danger_cmd}")
                await self._notify_protection(
                    event,
                    "危险命令拦截",
                    f"检测到危险命令: {danger_cmd}",
                    prompt_text
                )
                req.prompt = "用户请求已被安全系统阻止。请回复：'检测到危险命令，该操作已被阻止。'"
                
        except Exception as e:
            logger.error(f"[Aegis] LLM 请求拦截错误: {e}")
    
    @filter.on_llm_response()
    async def on_llm_response(self, event: AstrMessageEvent, resp: LLMResponse) -> None:
        """
        拦截 LLM 响应，检查是否包含危险内容
        """
        if not self.config.enabled:
            return
        
        try:
            response_text = resp.completion_text or ""
            
            # 检查响应中是否包含执行危险操作的代码
            dangerous_patterns = [
                (r'os\.system\s*\(\s*["\']rm\s+-rf', "系统命令执行 - 删除文件"),
                (r'subprocess\.call.*rm\s+-rf', "子进程调用 - 删除文件"),
                (r'open\s*\([^)]*["\']w["\'].*astrbot', "文件写入 - 核心文件"),
                (r'shutil\.(rmtree|move|copy).*astrbot', "文件操作 - 核心目录"),
            ]
            
            for pattern, desc in dangerous_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    logger.warning(f"[Aegis] 响应中包含危险代码: {desc}")
                    
                    # 替换响应
                    resp.completion_text = "⚠️ 原响应包含潜在危险操作，已被安全系统过滤。请通过合法方式操作文件。"
                    
                    await self._notify_protection(
                        event,
                        "危险代码过滤",
                        f"响应中包含: {desc}",
                        response_text[:200]
                    )
                    return
            
            # 检测隐私泄露
            has_leak, leak_types = self._detect_privacy_leak(response_text)
            if has_leak:
                logger.warning(f"[Aegis] 响应中包含隐私信息: {leak_types}")
                resp.completion_text = self._sanitize_privacy_info(response_text)
                
        except Exception as e:
            logger.error(f"[Aegis] LLM 响应拦截错误: {e}")
    
    # ============ 指令 ============
    
    @filter.command("aegis_status")
    async def aegis_status(self, event: AstrMessageEvent):
        """查看 Aegis 安全系统状态"""
        status_msg = f"""🛡️ **Aegis 安全系统状态**

📊 **基本状态**
- 运行状态: {'✅ 已启用' if self.config.enabled else '❌ 已禁用'}
- 安全模型: {self.config.model_provider or '未配置（使用本地规则）'}
- 阻止操作数: {len(self.blocked_operations)}

🔒 **保护规则**
- 受保护路径: {len(self.config.protected_paths)} 条
- 白名单路径: {len(self.config.allowed_paths)} 条
- 隐私检测规则: {len(self.config.privacy_patterns)} 条
- 危险命令规则: {len(self.config.dangerous_commands)} 条

💡 **使用说明**
- 使用 `/aegis_toggle` 启用/禁用保护
- 使用 `/aegis_log` 查看最近阻止记录
"""
        yield event.plain_result(status_msg)
    
    @filter.command("aegis_toggle")
    async def aegis_toggle(self, event: AstrMessageEvent):
        """切换 Aegis 保护状态"""
        self.config.enabled = not self.config.enabled
        self._save_config()
        
        status = "已启用" if self.config.enabled else "已禁用"
        yield event.plain_result(f"🛡️ Aegis 安全系统已{status}")
    
    @filter.command("aegis_log")
    async def aegis_log(self, event: AstrMessageEvent):
        """查看最近阻止的操作记录"""
        if not self.blocked_operations:
            yield event.plain_result("🛡️ 暂无阻止记录")
            return
        
        log_msg = "🛡️ **最近阻止的操作**\n\n"
        for i, op in enumerate(self.blocked_operations[-10:], 1):
            log_msg += f"{i}. **{op.get('action', '未知')}**\n"
            log_msg += f"   原因: {op.get('reason', '未知')}\n"
            log_msg += f"   时间: {op.get('timestamp', '未知')}\n\n"
        
        yield event.plain_result(log_msg)
    
    async def terminate(self):
        """插件卸载时调用"""
        logger.info("[Aegis] 安全守护者已停止")

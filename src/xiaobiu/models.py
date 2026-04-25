from __future__ import annotations

from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class SuningBaseModel(BaseModel):
  """苏宁智能家居API的基础数据模型
  
  继承自Pydantic的BaseModel，配置为:
  - 忽略额外字段 (extra="ignore")
  - 赋值时进行验证 (validate_assignment=True)
  """
  model_config = ConfigDict(extra="ignore", validate_assignment=True)


class LoginPageConfig(SuningBaseModel):
  """苏宁登录页面的配置信息
  
  包含登录过程中所需的各种密钥和标识符，这些信息通常从登录页面的JavaScript中提取
  """
  # 登录公钥，用于RSA加密
  login_pbk: str
  # RDSY(苏宁风控系统)的公钥
  rdsy_key: str
  # RDSY的应用代码
  rdsy_app_code: str
  # 第一步验证的标志
  step_flag: str
  # 第二步验证的标志
  step_two_flag: str
  # 第三步验证的标志
  step_three_flag: str
  # RDSY的场景ID
  rdsy_scene_id: str
  # 香港地区的RDSY场景ID
  rdsy_scene_id_yghk: str
  # 渠道标识
  channel: str
  # 账号检查的公钥
  check_account_key: str


class AuthState(SuningBaseModel):
  """苏宁登录认证状态
  
  保存登录过程中的各种票据和认证信息，可用于会话恢复
  """
  # 手机号码
  phone_number: str | None = None
  # 国际区号，默认为中国大陆(0086)
  international_code: str = "0086"
  # 风控检测标识，从浏览器JS环境获取
  detect: str = "passport_detect_js_is_error"
  # DFP(设备指纹)令牌，从浏览器JS环境获取
  dfp_token: str = "passport_dfpToken_js_is_error"
  # 风控类型，如需要验证码时会有值
  risk_type: str | None = None
  # 短信验证码票据
  sms_ticket: str | None = None
  # 登录票据
  login_ticket: str | None = None
  # 登录响应的完整数据
  login_response: dict[str, Any] | None = None
  # 状态最后更新时间(时间戳)
  updated_at: float | None = None


class CaptchaSolution(SuningBaseModel):
  """验证码解决方案
  
  包含验证码类型和值，用于提交验证码验证
  """
  # 验证码类型: iar(拼图验证)、slide(滑块验证)、image(图片验证)
  kind: str
  # 验证码的值/令牌
  value: str


class SignedRequestTemplate(SuningBaseModel):
  """已签名的请求模板
  
  从HAR文件中提取的请求模板，包含方法、URL、请求头和请求体
  用于模拟已签名的API请求
  """
  # HTTP方法(GET/POST等)
  method: str
  # 请求URL
  url: str
  # 请求头字典
  headers: dict[str, str] = Field(default_factory=dict)
  # 请求体内容
  body: str = ""
  # HAR文件路径(用于调试)
  har_path: str | None = None

  def build_headers(self) -> dict[str, str]:
    """构建请求头
    
    处理请求头，生成新的追踪ID，并过滤掉不需要的请求头
    
    Returns:
      处理后的请求头字典
    """
    # 生成新的追踪ID
    trace_id = uuid4().hex
    headers: dict[str, str] = {}
    for name, value in self.headers.items():
      lower_name = name.lower()
      # 跳过host、cookie、content-length等自动生成的请求头
      if lower_name in {"host", "cookie", "content-length"} or lower_name.startswith(":"):
        continue
      # 为追踪ID请求头生成新的值
      if lower_name in {"sntraceid", "hiro_trace_id"}:
        headers[name] = trace_id
        continue
      headers[name] = value
    return headers


class FamilyInfo(SuningBaseModel):
  """家庭信息
  
  表示苏宁智能家居中的一个家庭
  """
  # 家庭ID
  family_id: str
  # 家庭名称
  name: str
  # 原始API响应数据
  raw: dict[str, Any] = Field(default_factory=dict)


class HAClimatePreview(SuningBaseModel):
  """Home Assistant气候组件预览
  
  用于预览空调设备在Home Assistant中的表现
  """
  # 实体域
  entity_domain: str
  # 翻译键
  translation_key: str
  # 设备是否可用
  available: bool
  # HVAC模式
  hvac_mode: str | None = None
  # 当前温度
  current_temperature: float | None = None
  # 目标温度
  target_temperature: float | None = None
  # 风扇模式
  fan_mode: str | None = None
  # 摆风模式
  swing_mode: str | None = None
  # 预设模式
  preset_mode: str | None = None
  # 支持的功能预览列表
  supported_features_preview: list[str] = Field(default_factory=list)
  # 原始字段映射
  raw_mapping: dict[str, dict[str, Any]] = Field(default_factory=dict)
  # 备注信息
  notes: list[str] = Field(default_factory=list)


class AirConditionerStatus(SuningBaseModel):
  """空调设备状态
  
  表示苏宁智能家居中空调设备的完整状态信息
  """
  # 设备ID
  device_id: str
  # 设备名称
  name: str
  # 设备型号
  model: str | None = None
  # 所属家庭ID
  family_id: str | None = None
  # 所属组ID
  group_id: str | None = None
  # 所属组名称
  group_name: str | None = None
  # 类别ID
  category_id: str | None = None
  # 设备是否可用
  available: bool
  # 设备是否在线
  online: bool
  # 状态摘要
  summary: str | None = None
  # 设备记录时间
  device_record_time: str | None = None
  # 状态刷新时间
  refresh_time: str | None = None
  # 电源是否开启
  power_on: bool | None = None
  # 当前室温
  current_temperature: float | None = None
  # 目标温度
  target_temperature: float | None = None
  # 室外温度
  outdoor_temperature: float | None = None
  # 原始模式值
  mode_raw: str | None = None
  # 原始风扇模式值
  fan_mode_raw: str | None = None
  # 水平摆风
  swing_horizontal: bool | None = None
  # 垂直摆风
  swing_vertical: bool | None = None
  # 节能模式是否开启
  eco_enabled: bool | None = None
  # 净化功能是否开启
  purify_enabled: bool | None = None
  # 新风功能是否开启
  fresh_air_enabled: bool | None = None
  # 电辅热功能是否开启
  electric_heating_enabled: bool | None = None
  # Home Assistant气候组件预览
  ha_climate_preview: HAClimatePreview | None = None
  # 原始状态数据
  raw_status: dict[str, Any] = Field(default_factory=dict)
  # 原始设备数据
  raw_device: dict[str, Any] = Field(default_factory=dict)


class SerializedCookie(SuningBaseModel):
  """序列化的Cookie
  
  用于持久化保存HTTP会话Cookie
  """
  # Cookie名称
  name: str
  # Cookie值
  value: str
  # Cookie域名
  domain: str
  # Cookie路径
  path: str
  # 是否仅HTTPS
  secure: bool = False
  # 过期时间
  expires: int | float | None = None
  # 其他属性
  rest: dict[str, Any] = Field(default_factory=dict)


class PersistedSessionState(SuningBaseModel):
  """持久化的会话状态
  
  用于保存和恢复登录会话
  """
  # 认证状态
  state: AuthState = Field(default_factory=AuthState)
  # Cookie列表
  cookies: list[SerializedCookie] = Field(default_factory=list)


class CaptchaBridgeResult(SuningBaseModel):
  """验证码桥接结果
  
  通过浏览器完成验证码后返回的结果
  """
  # 验证码令牌
  token: str
  # 风控检测标识
  detect: str | None = None
  # DFP令牌
  dfp_token: str | None = None

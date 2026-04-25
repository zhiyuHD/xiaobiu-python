#!/usr/bin/env python3
"""打开儿童房空调的脚本"""
# 调用dev环境的包
from src.xiaobiu import SuningSmartHomeClient

# 创建客户端并加载会话
client = SuningSmartHomeClient(
    state_path=".suning-session.json",
    load_state=True,
)

# 获取家庭列表
families = client.list_family_infos()
print(f"找到 {len(families)} 个家庭:")
for i, family in enumerate(families, 1):
    print(f"  {i}. {family.name} (ID: {family.family_id})")

# 使用第一个家庭
family = families[0]
print(f"\n使用家庭: {family.name}")

# 获取家庭的设备列表
print(f"\n获取 {family.name} 的设备列表...")
devices_response = client.list_devices(family.family_id)
devices = devices_response.get("responseData", {}).get("devices", [])

if not devices:
    print(f"{family.name} 中没有设备")
    exit(1)

print(f"\n找到 {len(devices)} 个设备:")
for i, device in enumerate(devices, 1):
    print(f"  {i}. {device.get('name')} (ID: {device.get('id')})")

# 查找空调设备
ac_device = None
for device in devices:
    device_name = device.get("name", "")
    if "空调" in device_name:
        ac_device = device
        print(f"\n找到空调: {device_name}")
        break

if not ac_device:
    print("\n未找到空调设备")
    exit(1)

# 获取空调状态
print(f"\n获取空调状态...")
ac_status = client.get_air_conditioner_status(
    family.family_id,
    device_id=ac_device.get("id")
)

print(f"\n空调状态:")
print(f"  设备名称: {ac_status.name}")
print(f"  电源状态: {'开启' if ac_status.power_on else '关闭'}")
print(f"  当前温度: {ac_status.current_temperature}°C")
print(f"  目标温度: {ac_status.target_temperature}°C")
device_id = ac_status.device_id
model_id = ac_status.raw_device.get("modelId")
# 如果已经开启，则不需要操作
if ac_status.power_on:
    print("\n空调已经开启，我要关掉它！")
    result = client.set_air_conditioner_power(
        device_id=device_id,
        model_id=model_id,
        power_on=False
    )
    print(f"\n操作结果: {result}")
    exit(0)

# 打开空调
print(f"\n正在打开空调...")
result = client.set_air_conditioner_temperature(
    device_id=device_id,
    model_id=model_id,
    temperature=26.0
)

result = client.set_air_conditioner_power(
    device_id=device_id,
    model_id=model_id,
    power_on=True
)

print(f"\n操作结果: {result}")
print("\n空调已打开！")

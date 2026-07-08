# home

Toolbox 首页管理服务 — 整合部署入口。

> 本工具使用 [WorkBuddy](https://www.codebuddy.cn/) AI 开发助手开发完成。

## 功能

- **单端口整合**：通过 `DispatcherMiddleware` 把所有子模块挂载到 `/<id>/` 子路径，访问只走一个端口
- **模块自动发现**：扫描仓库中含 `module.json` 的子目录，自动注册挂载
- **版本检测**：拉取 GitHub 远程 `module.json` 对比语义化版本，卡片显示更新角标
- **新模块发现**：调用 GitHub Contents API 检测远程有而本地无的模块目录
- **模块切换**：左上角下拉菜单，区分已安装 / 未安装状态

## 部署

```bash
# 整合部署（推荐）
./start-all.sh    # 从仓库根目录启动，访问 http://localhost:5001

# 或单独启动首页服务
cd home && ./start.sh
```

端口 5001（避开 macOS AirPlay 占用的 5000）。

## module.json 规范

每个子模块根目录放一份 `module.json`：

| 字段 | 说明 |
|------|------|
| id | 唯一标识，用作挂载路径 |
| name | 卡片标题 |
| description | 一句话介绍 |
| version | 语义化版本（x.y.z） |
| category | 分类 |
| port | 独立部署端口 |
| entry | 入口文件 |

新增模块只需创建含 `module.json` 的目录，重启即自动识别。

## 技术栈

| 层 | 技术 |
|----|------|
| 后端 | Python 3 / Flask + Werkzeug DispatcherMiddleware |
| 前端 | HTML / CSS / JavaScript 原生 |
| 远程检测 | GitHub raw + Contents API |

# [How to Fix Invisible Mouse & White Screen in HOI4 on Linux (Steam)|如何在 Linux (Steam) 上解决《钢铁雄心4》鼠标隐形与开局白屏问题](https://github.com/cufezhusy/cufezhusy.github.io/issues/25)

If you play Hearts of Iron IV (HOI4) on Linux via Steam, you might encounter a frustrating bug: your mouse cursor disappears inside the game, and when you quit, it remains invisible on your desktop.

Attempting to fix this by changing display settings (like switching to Borderless Windowed) can sometimes cause a blank white screen on startup.

Here is the quick, clean fix using the Paradox Launcher—no terminal commands required!

The Cause
On Linux (especially under Wayland or modern X11 compositors), HOI4’s native Linux renderer struggles with hardware cursor locking. Changing display modes can corrupt local display caches, causing the game engine to freeze on a white screen when initializing graphics.

The Solution
Step 1: Clear the Game Cache via Paradox Launcher
If your game is stuck on a white screen after changing video settings:

Launch Hearts of Iron IV from Steam to open the Paradox Launcher.

Go to Game Settings on the left menu.

Scroll down to the bottom and click Clear User Directory (or Clear Cache).

Confirm the reset. (Note: This resets graphics and UI settings to default without deleting your save files).

Step 2: Prevent the Invisible Mouse Bug
To keep your cursor visible during and after gameplay:

Open Steam, right-click Hearts of Iron IV > Properties.

Go to the Compatibility tab.

Check "Force the use of a specific Steam Play compatibility tool".

Select Proton Experimental or Proton 9.0.

Running the game through Proton uses DirectX instead of the native OpenGL/Linux renderer, completely preventing hardware cursor lockup!


在 Linux 系统上通过 Steam 游玩《钢铁雄心4》（Hearts of Iron IV / HOI4）时，很多玩家会遇到一个让人头疼的 Bug：游戏内鼠标指针完全消失，甚至退出游戏后，系统桌面的鼠标也依然不可见。

如果你尝试通过修改显示模式（比如切换到无边框窗口）来修复鼠标，往往还会导致游戏启动时出现全屏白屏卡死。

这里提供一个最简单且干净的解决方案，只需通过 P 社启动器（Paradox Launcher）即可完成，无需使用复杂的终端命令！

问题原因
在 Linux 环境下（尤其是使用 Wayland 或新型 X11 窗口管理器时），《钢铁雄心4》的原生 Linux 渲染引擎在处理硬件鼠标锁定机制时存在漏洞。切换显示模式容易导致本地图形缓存损坏，从而引发启动时的白屏卡死。

解决步骤
第一步：通过 P 社启动器清理缓存（解决白屏）
如果修改显示设置后游戏启动变白屏：

从 Steam 启动 Hearts of Iron IV，打开 Paradox 启动器。

点击左侧菜单的 游戏设置（Game Settings）。

滚动到页面最下方，点击 清除用户目录（Clear User Directory）或 清除缓存（Clear Cache）。

确认重置。(注：这只会恢复默认画面和 UI 设置，不会删除你的游戏存档)。

第二步：彻底解决鼠标隐形问题
为确保游戏内和退出后的鼠标始终正常显示：

打开 Steam，右键点击 Hearts of Iron IV > 属性。

切换到 兼容性 选项卡。

勾选 “强制使用特定的 Steam Play 兼容性工具”。

在下拉菜单中选择 Proton Experimental 或 Proton 9.0。

通过 Proton 运行 Windows 版本的游戏会改用 DirectX 渲染，彻底避免了原生 Linux 版的硬件鼠标锁死问题！
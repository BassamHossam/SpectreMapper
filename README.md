![SpectreMapper](assets/demo.gif)

<h1 align="center">🕶️ SpectreMapper</h1>
<p align="center">
<b>High-Performance PE Manual Mapping & Memory Research Tool</b><br>
Engineered in C · Advanced Windows Internals · Pure Stealth Logic
</p>
<p align="center">
<img src="https://img.shields.io/badge/Language-C-blue?style=for-the-badge">
<img src="https://img.shields.io/badge/Platform-Windows-informational?style=for-the-badge">
<img src="https://img.shields.io/badge/Architecture-x64-important?style=for-the-badge">
<img src="https://img.shields.io/badge/Stealth-Manual_Loading-red?style=for-the-badge">
</p>
<hr>
<h2>📌 Executive Summary</h2>
<p>
<b>SpectreMapper</b> is a surgical <b>Portable Executable (PE) Manual Mapper</b> designed for x64 Windows environments.
Unlike traditional injection methods that rely on the loud and easily detectable <code>LoadLibrary</code> API, SpectreMapper replicates the entire Windows OS Loader's logic in user-land.
</p>
<p>
This project is a deep-dive into <b>low-level memory manipulation</b>, demonstrating how to transform a raw EXE buffer into a fully functional running process thread by manually handling headers, sections, relocations, and complex imports.
</p>
<hr>
<h2>🧠 Technical Capabilities</h2>
<ul>
<li><b>Recursive IAT Resolution:</b> Manually walks the Import Address Table and resolves dependencies, including <b>C-Runtime (CRT)</b> libraries like <code>VCRUNTIME140.dll</code> and <code>api-ms-win-crt-runtime-l1-1-0.dll</code>.</li>
<li><b>Custom Base Relocation Engine:</b> Surgical patching of hardcoded addresses (Delta application) to support ASLR and non-preferred base address mapping.</li>
<li><b>Zero-Disk Footprint:</b> The payload exists only in the virtual memory of the target, evading traditional file-based scanners.</li>
<li><b>Modular PE Parser:</b> A custom-built engine to interpret DOS, NT, and Section headers without standard helper libraries.</li>
</ul>
<hr>
<h2>📂 Project Structure</h2>
<pre>
SpectreMapper/
│
├── SpectreMapper/ # Core Injector Source
│ ├── src/
│ │ ├── main.c 
│ │ ├── PE_parser.c 
│ │ ├── injector.c 
│ └── include/
│
├── TestPayload/ # Sample Payload (MessageBox Example)
│ └── main.c # Optimized for manual mapping (/GS-)
│
├── assets/ # Research Visuals (Images & Gifs)
├── SpectreMapper.sln # Unified Visual Studio Solution
└── README.md
</pre>
<hr>
<h2>🛠️ Build & Configuration</h2>
<h3>1. Payload Preparation</h3>
To ensure the payload is compatible with manual mapping, it must be compiled with specific flags:
<ul>
<li><b>Disable Security Check:</b> <code>/GS-</code></li>
<li><b>Dynamic Base:</b> <code>/DYNAMICBASE</code> (Required for <code>.reloc</code> generation)</li>
<li><b>Fixed Base Address:</b> <code>/FIXED:NO</code></li>
</ul>
<h3>2. Building the Project</h3>
<ol>
<li>Open <code>SpectreMapper.sln</code> in <b>Visual Studio 2022</b>.</li>
<li>Set the target architecture to <b>x64</b>.</li>
<li>Build the solution to generate <code>SpectreMapper.exe</code> and <code>TestPayload.exe</code>.</li>
</ol>
<hr>
<h2>▶️ Usage & Proof of Concept</h2>
<pre>
SpectreMapper.exe &lt;TargetProcess.exe&gt; &lt;Payload.exe&gt;
</pre>
<b>Live Research Example:</b>
<pre>
SpectreMapper.exe notepad.exe TestPayload.exe
</pre>
<p align="center">
<img src="assets/execution_log.gif" alt="Execution Log Screenshot" width="80%">
<br>
<i>Figure 1: Successful mapping showing Delta calculation and IAT resolution for CRT libraries.</i>
</p>
<hr>
<h2>🎯 Research Goals</h2>
<ul>
<li>Analyze how Windows handles <code>IMAGE_BASE_RELOCATION</code> blocks.</li>
<li>Observe EDR behavior when encountering <b>Unbacked Executable Memory</b>.</li>
<li>Perfecting the art of <b>Reflective Loading</b> in the x64 era.</li>
</ul>
<hr>
<h2>⚠️ Legal & Ethical Disclaimer</h2>
<p>
This repository is for <b>Security Research and Educational Purposes only</b>.
The techniques demonstrated are intended for Malware Analysts, Red Teamers, and Windows Internals enthusiasts.
The author is not responsible for any misuse or illegal activities conducted with this code.
</p>
<hr>
<p align="center">
<b>Researcher:</b> BassamHossam (ufo)<br>
<i>Mastering the Memory Abyss 🖕🔥</i>
</p>

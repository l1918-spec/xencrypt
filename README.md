# Xencrypt
### PowerShell Crypter v1.0

## Authors

- **Xentropy** ([Twitter: @SamuelAnttila](http://twitter.com/SamuelAnttila))  
- **SecForce** ([Twitter: @SECFORCE_LTD](http://twitter.com/SECFORCE_LTD))

For a deep dive into the design and step-by-step guidance on how to build your own crypter, check out this article: [Write a Crypter in Any Language](https://netsec.expert/2020/02/06/write-a-crypter-in-any-language.html).

---

## ⚠️ Disclaimer

This tool is **not intended for malicious use.**  
It is published under the **GPLv3 license** to encourage learning and modifications for legitimate purposes only.  

This project serves as a demonstration of how easy it is to write a crypter. It works as designed, but **no additional patches or customization** will be provided to fit other purposes. If you're serious about this, explore and modify the code yourself.

---

## Features

Xencrypt provides:

- **AMSI bypass** and evasion of modern antivirus solutions (tested on VirusTotal at the time of writing).
- **Compression and encryption** of PowerShell scripts.
- Minimal or **negative performance overhead** (due to compression).
- **Obfuscation** with randomized variable names and decryption stubs.
- **High entropy** through randomized encryption, compression, and statement ordering.
- **Easy customization** for creating your own crypter variant.
- Support for **recursive layering**, tested with up to 500 layers.
- Compatibility with both `Import-Module` and direct execution (as long as the original script supports it).
- Distributed as a **single file**, ensuring portability.
- Licensed under **GPLv3** – completely free and open-source!

### Caveat
While Xencrypt is powerful, it’s not a universal solution for all configurations. **Use at your own risk!**

---

## 📸 Screenshots

Bypassing AMSI:  
![Bypass](./bypass.png)

Full Undetectability (FUD):  
![FUD](./fud.png)

---

## 🛠️ Usage

To get started, first import the module and run the script:

```powershell
Import-Module ./xencrypt.ps1
Invoke-Xencrypt -InFile invoke-mimikatz.ps1 -OutFile xenmimi.ps1

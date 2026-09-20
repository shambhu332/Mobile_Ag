import logging
import zipfile
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)

class PackerDetector:
    """
    Detects known DEX packers and protectors.
    """

    # Signatures can be native libraries (.so), specific stub classes, or manifest entries.
    PACKER_SIGNATURES = {
        "Qihoo/360 Jiagu": ["libjiagu.so", "libjiagu_x86.so", "com.stub.StubApp"],
        "Tencent/Legu": ["libshell.so", "libshellx.so", "libtxsec.so", "com.tencent.StubShell"],
        "Baidu": ["libbaiduprotect.so", "com.baidu.protect.A"],
        "Bangcle/SecNeo": ["libsecexe.so", "libsecmain.so", "libSecEnhance.so", "com.secneo.apkwrapper"],
        "Ijiami": ["libexec.so", "libexecmain.so", "ijiami.dat"],
        "DexProtector": ["libdexprotector.so", "dexprotector"],
        "Alibaba": ["libmobisec.so", "libali-s.so"],
    }

    def __init__(self) -> None:
        pass

    def detect(self, apk_path: str, decompiled_path: str) -> Dict[str, Any]:
        """
        Detects if the APK is packed.

        Args:
            apk_path: Path to the original APK file.
            decompiled_path: Path to the decompiled APK directory.

        Returns:
            A dictionary containing packer detection info.
        """
        is_packed = False
        packer_name = "None"
        evidence = []
        unpack_instructions = ""

        # Check inside APK via zipfile without full extraction
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                file_list = apk_zip.namelist()
                for packer, signatures in self.PACKER_SIGNATURES.items():
                    for sig in signatures:
                        # Check if signature matches any file in the APK
                        if any(sig in f for f in file_list):
                            is_packed = True
                            packer_name = packer
                            evidence.append(sig)
        except Exception as e:
            logger.error(f"Error reading APK zip for packer detection: {e}")

        # Fallback check on decompiled directory (smali paths, manifest)
        dec_path = Path(decompiled_path)
        if not is_packed and dec_path.exists():
            for packer, signatures in self.PACKER_SIGNATURES.items():
                for sig in signatures:
                    # simplistic check for class names in smali paths or known files
                    sig_path_format = sig.replace('.', '/')
                    if list(dec_path.rglob(f"*{sig}*")) or list(dec_path.rglob(f"*{sig_path_format}*")):
                        is_packed = True
                        packer_name = packer
                        evidence.append(sig)
                        break

        if is_packed:
            unpack_instructions = f"Detected {packer_name}. Automated unpacking is not supported natively. Consider using dynamic dumping tools like Frida, FRIDA-DEXDump, or BlackDex."
            logger.info(f"Packer detected: {packer_name}")

        return {
            "is_packed": is_packed,
            "packer_name": packer_name,
            "evidence": list(set(evidence)),
            "unpack_instructions": unpack_instructions
        }

"""Reachability filter — checks if vulnerable code is actually reachable."""

import asyncio
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class ReachabilityFilter:
    """Checks whether the class/method containing a finding is referenced
    elsewhere in the codebase. Dead code findings get low scores.
    """

    async def check(
        self,
        finding_title: str,
        affected_component: str,
        file_path: str,
        decompiled_path: str,
    ) -> tuple[float, str]:
        """Check if the affected component is reachable from other code.

        Args:
            finding_title: Finding title for logging.
            affected_component: Fully qualified class or method name.
            file_path: Source file path of the finding.
            decompiled_path: Root of decompiled source tree.

        Returns:
            Tuple of (score 0.0–1.0, reason_string).
            Low score = likely dead/unreachable code.
        """
        if not affected_component or not decompiled_path:
            return 0.5, "Insufficient data for reachability check"

        src = Path(decompiled_path)
        if not src.exists():
            return 0.5, "Decompiled path not found"

        # Extract simple class name from fully-qualified name
        class_name = affected_component.rsplit(".", 1)[-1] if "." in affected_component else affected_component

        if not class_name or len(class_name) < 2:
            return 0.5, "Class name too short for meaningful reachability check"

        try:
            ref_count = await self._count_references(class_name, src, file_path)
        except Exception as exc:
            logger.warning("Reachability check error for %s: %s", affected_component, exc)
            return 0.5, f"Error during reachability check: {exc}"

        if ref_count == 0:
            return 0.15, f"No references to '{class_name}' found — likely dead code"
        elif ref_count <= 2:
            return 0.5, f"Only {ref_count} reference(s) to '{class_name}' — limited reachability"
        elif ref_count <= 5:
            return 0.75, f"{ref_count} references to '{class_name}' — moderately reachable"
        else:
            return 0.95, f"{ref_count} references to '{class_name}' — widely reachable"

    async def _count_references(
        self,
        class_name: str,
        source_root: Path,
        exclude_file: str,
    ) -> int:
        """Count how many source files reference the given class name.

        Uses `grep -rl` for speed.  Falls back to Python walk if grep
        is unavailable.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "grep", "-rl", "--include=*.java", "--include=*.kt",
                class_name, str(source_root),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            files = [
                f for f in stdout.decode(errors="replace").strip().splitlines()
                if f and f != exclude_file
            ]
            return len(files)
        except FileNotFoundError:
            # grep not available — fallback
            return await self._python_grep(class_name, source_root, exclude_file)
        except asyncio.TimeoutError:
            logger.warning("Reachability grep timed out for %s", class_name)
            return 0

    async def _python_grep(
        self,
        class_name: str,
        source_root: Path,
        exclude_file: str,
    ) -> int:
        """Pure-Python fallback for reference counting."""
        count = 0
        for ext in ("*.java", "*.kt"):
            for fp in source_root.rglob(ext):
                if str(fp) == exclude_file:
                    continue
                try:
                    text = fp.read_text(errors="replace")
                    if class_name in text:
                        count += 1
                except OSError:
                    continue
        return count

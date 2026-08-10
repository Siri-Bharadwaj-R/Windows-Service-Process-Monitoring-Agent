"""
Digital signature verification utilities for the
Windows Service & Process Monitoring Agent.
"""

import json
import subprocess

from utils.logger import Logger


class SignatureVerifier:
    """
    Verifies Windows executable digital signatures
    using PowerShell Authenticode verification.
    """

    def __init__(self) -> None:
        """
        Initialize the signature verifier.
        """

        self.logger = Logger()

        self.findings: list[dict[str, str]] = []

        self.signature_cache: dict[
            str,
            dict[str, object]
        ] = {}

        # Keeps track of executable paths that already
        # generated a finding during the current scan.
        self.finding_paths: set[str] = set()

    def verify(
        self,
        executable_path: str | None,
    ) -> dict[str, object]:
        """
        Verify the digital signature of one executable.

        Args:
            executable_path:
                Full executable path.

        Returns:
            Signature verification result.
        """

        if not executable_path:

            return {
                "path": executable_path,
                "signed": False,
                "status": "NoPath",
                "publisher": None,
            }

        normalized_path = executable_path.strip()

        if not normalized_path:

            return {
                "path": executable_path,
                "signed": False,
                "status": "NoPath",
                "publisher": None,
            }

        if not normalized_path.lower().endswith(".exe"):

            return {
                "path": executable_path,
                "signed": False,
                "status": "Unsupported",
                "publisher": None,
            }

        cache_key = normalized_path.lower()

        if cache_key in self.signature_cache:

            return self.signature_cache[
                cache_key
            ].copy()

        results = self._verify_batch(
            [normalized_path]
        )

        result = results.get(
            cache_key,
            {
                "path": executable_path,
                "signed": False,
                "status": "Unknown",
                "publisher": None,
            },
        )

        self.signature_cache[
            cache_key
        ] = result.copy()

        return result.copy()

    def _verify_batch(
        self,
        executable_paths: list[str],
    ) -> dict[str, dict[str, object]]:
        """
        Verify multiple executable signatures
        using a single PowerShell process.

        Args:
            executable_paths:
                Unique executable paths.

        Returns:
            Mapping of normalized paths to
            signature results.
        """

        if not executable_paths:
            return {}

        try:

            paths_json = json.dumps(
                executable_paths
            )

            powershell_script = r"""
$paths = @'
__PATH_DATA__
'@ | ConvertFrom-Json

$results = foreach ($path in $paths) {

    $signature = Get-AuthenticodeSignature `
        -LiteralPath $path `
        -ErrorAction SilentlyContinue

    $publisher = ""

    if ($null -ne $signature.SignerCertificate) {
        $publisher = `
            $signature.SignerCertificate.Subject
    }

    [PSCustomObject]@{
        Path = $path
        Status = $signature.Status.ToString()
        Publisher = $publisher
    }
}

$results | ConvertTo-Json -Compress
"""

            powershell_script = powershell_script.replace(
                "__PATH_DATA__",
                paths_json,
            )

            command = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                powershell_script,
            ]

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=60,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            if result.returncode != 0:

                self.logger.warning(
                    "Batch PowerShell signature "
                    "verification failed."
                )

                return self._create_unknown_results(
                    executable_paths,
                    "VerificationError",
                )

            output = result.stdout.strip()

            if not output:

                return self._create_unknown_results(
                    executable_paths,
                    "Unknown",
                )

            try:

                raw_results = json.loads(
                    output
                )

            except json.JSONDecodeError:

                self.logger.warning(
                    "Unable to parse PowerShell "
                    "signature verification output."
                )

                return self._create_unknown_results(
                    executable_paths,
                    "ParseError",
                )

            if isinstance(
                raw_results,
                dict,
            ):

                raw_results = [
                    raw_results
                ]

            results: dict[
                str,
                dict[str, object]
            ] = {}

            for item in raw_results:

                path = item.get(
                    "Path"
                )

                if not path:
                    continue

                status = str(
                    item.get(
                        "Status",
                        "Unknown",
                    )
                )

                publisher = (
                    item.get("Publisher")
                    or None
                )

                verification_result = {
                    "path": path,
                    "signed": (
                        status.lower()
                        == "valid"
                    ),
                    "status": status,
                    "publisher": publisher,
                }

                results[
                    str(path).lower()
                ] = verification_result

            # Fill in anything PowerShell did not return.
            for path in executable_paths:

                cache_key = path.lower()

                if cache_key not in results:

                    results[cache_key] = {
                        "path": path,
                        "signed": False,
                        "status": "Unknown",
                        "publisher": None,
                    }

            return results

        except subprocess.TimeoutExpired:

            self.logger.warning(
                "Batch digital signature "
                "verification timed out."
            )

            return self._create_unknown_results(
                executable_paths,
                "Timeout",
            )

        except Exception as error:

            self.logger.error(
                "Batch signature verification error: "
                f"{error}"
            )

            return self._create_unknown_results(
                executable_paths,
                "Error",
            )

    def _create_unknown_results(
        self,
        executable_paths: list[str],
        status: str,
    ) -> dict[str, dict[str, object]]:
        """
        Create fallback results when batch
        verification cannot be completed.
        """

        results: dict[
            str,
            dict[str, object]
        ] = {}

        for path in executable_paths:

            results[path.lower()] = {
                "path": path,
                "signed": False,
                "status": status,
                "publisher": None,
            }

        return results

    def verify_processes(
        self,
        processes: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        """
        Verify executable signatures for
        collected processes.

        Each unique executable path is verified
        only once using one PowerShell process.

        Args:
            processes:
                List of collected process information.

        Returns:
            Signature results associated with
            the collected processes.
        """

        self.logger.info(
            "Starting digital signature verification..."
        )

        self.findings.clear()
        self.finding_paths.clear()

        # -------------------------------------------------
        # Collect unique executable paths
        # -------------------------------------------------

        unique_paths: dict[str, str] = {}

        for process in processes:

            executable_path = process.get(
                "exe"
            )

            if not isinstance(
                executable_path,
                str,
            ):
                continue

            executable_path = (
                executable_path.strip()
            )

            if not executable_path:
                continue

            if not executable_path.lower().endswith(
                ".exe"
            ):
                continue

            cache_key = executable_path.lower()

            if cache_key not in self.signature_cache:

                unique_paths[
                    cache_key
                ] = executable_path

        # -------------------------------------------------
        # Batch verification
        # -------------------------------------------------

        if unique_paths:

            batch_results = self._verify_batch(
                list(unique_paths.values())
            )

            self.signature_cache.update(
                batch_results
            )

        # -------------------------------------------------
        # Associate results with processes
        # -------------------------------------------------

        results: list[
            dict[str, object]
        ] = []

        for process in processes:

            executable_path = process.get(
                "exe"
            )

            if not isinstance(
                executable_path,
                str,
            ):
                continue

            executable_path = (
                executable_path.strip()
            )

            if not executable_path:
                continue

            # Ignore pseudo-processes such as:
            # Registry and MemCompression.
            if not executable_path.lower().endswith(
                ".exe"
            ):
                continue

            cache_key = executable_path.lower()

            result = self.signature_cache.get(
                cache_key
            )

            if result is None:

                result = {
                    "path": executable_path,
                    "signed": False,
                    "status": "Unknown",
                    "publisher": None,
                }

            process_result = result.copy()

            process_result["pid"] = (
                process.get("pid")
            )

            process_result["process_name"] = (
                process.get("name")
            )

            results.append(
                process_result
            )

            self._create_finding(
                process_result
            )

        self.logger.info(
            "Digital signature verification "
            "completed. "
            f"{len(results)} executables checked. "
            f"{len(unique_paths)} unique paths verified."
        )

        return results

    def _create_finding(
        self,
        result: dict[str, object],
    ) -> None:
        """
        Create a security finding for an
        unsigned executable.

        Only one finding is created for each
        unique executable path.
        """

        status = str(
            result.get(
                "status",
                "",
            )
        )

        if status != "NotSigned":
            return

        executable_path = str(
            result.get("path")
            or ""
        )

        finding_key = executable_path.lower()

        if finding_key in self.finding_paths:
            return

        self.finding_paths.add(
            finding_key
        )

        process_name = (
            result.get(
                "process_name"
            )
            or "Unknown"
        )

        self.findings.append(
            {
                "severity": "MEDIUM",
                "category": "Digital Signature",
                "title": "Unsigned Executable",
                "description":
                f"{process_name} is running "
                f"without a valid digital signature "
                f"from '{executable_path}'.",
                "recommendation":
                "Verify the executable's origin "
                "and determine whether it is "
                "authorized.",
            }
        )

        self.logger.warning(
            "[MEDIUM] Unsigned executable detected: "
            f"{process_name}"
        )

    def get_findings(
        self,
    ) -> list[dict[str, str]]:
        """
        Return findings generated by
        signature verification.
        """

        return self.findings
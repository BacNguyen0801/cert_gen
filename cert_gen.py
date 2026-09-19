#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
from enum import Enum
from pathlib import Path


# ============================================================
# Replacement modes
# ============================================================

class ReplacementMode(Enum):
    ALL = "ALL"
    IMI_DEVICE = "IMI_DEVICE"
    DEVICE = "DEVICE"


# ============================================================
# OpenSSL wrapper
# ============================================================

class OpenSSL:
    def __init__(self, executable="openssl"):
        self.executable = executable
        self._check_openssl()

    def _check_openssl(self):
        try:
            result = subprocess.run(
                [self.executable, "version"],
                capture_output=True,
                text=True,
                check=True,
            )

            print(f"[OPENSSL] {result.stdout.strip()}")

        except FileNotFoundError:
            raise RuntimeError(
                f"OpenSSL executable not found: {self.executable}\n"
                "Use --openssl or configure openssl.path in input.json."
            )

        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                f"Cannot execute OpenSSL: {self.executable}\n"
                f"{exc.stderr}"
            )

    def run(self, args):
        command = [self.executable] + [str(x) for x in args]

        print("\n[CMD]")
        print(
            " ".join(
                f'"{x}"' if " " in x else x
                for x in command
            )
        )

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print("\n[OPENSSL ERROR]")
            print(result.stderr)

            raise RuntimeError(
                f"OpenSSL command failed with return code "
                f"{result.returncode}"
            )

        if result.stdout.strip():
            print(result.stdout.strip())

        return result


# ============================================================
# Certificate Generator
# ============================================================

class CertificateGenerator:

    def __init__(
        self,
        config,
        output_dir,
        openssl_path="openssl",
    ):
        self.config = config
        self.output_dir = Path(output_dir)

        self.openssl = OpenSSL(openssl_path)

        self.output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

    # --------------------------------------------------------
    # Utilities
    # --------------------------------------------------------

    @staticmethod
    def _prepare_dir(path):
        path = Path(path)
        path.mkdir(
            parents=True,
            exist_ok=True,
        )
        return path

    @staticmethod
    def _remove_file(path):
        path = Path(path)

        if path.exists():
            path.unlink()

    @staticmethod
    def _require_file(path, description):
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(
                f"{description} not found: {path}"
            )

        return path

    def _write_text(self, path, content):
        path = Path(path)

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        path.write_text(
            content,
            encoding="utf-8",
        )

    # --------------------------------------------------------
    # CRT -> DER
    # --------------------------------------------------------

    def _convert_crt_to_der(self, cert_file):
        """
        Convert X.509 certificate from PEM (.crt)
        to binary DER (.der).

        Example:

            device.crt
                |
                v
            device.der

        The DER file contains the raw binary X.509
        certificate and can be used as payload data
        for UDS flashing.
        """

        cert_file = self._require_file(
            cert_file,
            "Certificate",
        )

        der_file = Path(cert_file).with_suffix(".der")

        print(
            f"\n[DER] Convert certificate:"
            f"\n      {cert_file}"
            f"\n      -> {der_file}"
        )

        self.openssl.run([
            "x509",
            "-in",
            cert_file,
            "-outform",
            "DER",
            "-out",
            der_file,
        ])

        self._require_file(
            der_file,
            "DER certificate",
        )

        print(
            f"[DER] Generated: {der_file}"
            f" ({der_file.stat().st_size} bytes)"
        )

        return der_file

    # --------------------------------------------------------
    # Config helpers
    # --------------------------------------------------------

    def _root_config(self):
        return self.config.get("root", {})

    def _imi_config(self):
        return self.config.get("imi", {})

    def _device_config(self):
        return self.config.get("device", {})

    # --------------------------------------------------------
    # Subject helper
    # --------------------------------------------------------

    @staticmethod
    def _format_subject(subject):
        """
        Convert subject configuration into OpenSSL -subj format.

        Supported input:

        1. String:

            "/C=VN/O=MyCompany/OU=PKI/CN=MyCompany Root CA"

        2. Dictionary:

            {
                "C": "VN",
                "O": "MyCompany",
                "OU": "PKI",
                "CN": "MyCompany Root CA"
            }
        """

        if isinstance(subject, str):
            subject = subject.strip()

            if not subject:
                raise ValueError(
                    "Subject cannot be empty."
                )

            return subject

        if isinstance(subject, dict):
            parts = []

            for key, value in subject.items():

                if value is None:
                    continue

                key = str(key).strip()

                if not key:
                    continue

                value = str(value)

                value = value.replace(
                    "\\",
                    "\\\\",
                )

                value = value.replace(
                    "/",
                    "\\/",
                )

                parts.append(
                    f"{key}={value}"
                )

            if not parts:
                raise ValueError(
                    "Subject dictionary cannot be empty."
                )

            return "/" + "/".join(parts)

        raise ValueError(
            "Invalid subject format. "
            "Expected string or dictionary."
        )

    # ========================================================
    # PUBLIC API
    # ========================================================

    def generate(self):
        """
        Generate completely new:

            Root
              |
              +-- IMI
                    |
                    +-- Device
        """

        print("\n========================================")
        print(" GENERATE NEW CERTIFICATE SET")
        print("========================================")

        root_dir = self.output_dir / "root"
        imi_dir = self.output_dir / "imi"
        device_dir = self.output_dir / "device"

        self._prepare_dir(root_dir)
        self._prepare_dir(imi_dir)
        self._prepare_dir(device_dir)

        # 1. Root
        root = self._generate_root(
            root_dir
        )

        # 2. IMI
        imi = self._generate_imi(
            root_cert=root["cert"],
            root_key=root["key"],
            output_dir=imi_dir,
        )

        # 3. Device
        device = self._generate_device(
            imi_cert=imi["cert"],
            imi_key=imi["key"],
            output_dir=device_dir,
        )

        # 4. Chain
        chain = self._create_chain(
            root_cert=root["cert"],
            imi_cert=imi["cert"],
            device_cert=device["cert"],
            output_dir=self.output_dir,
        )

        # 5. Verify
        self._verify_chain(
            root_cert=root["cert"],
            imi_cert=imi["cert"],
            device_cert=device["cert"],
        )

        print("\n[OK] Certificate generation completed.")

        return {
            "root": root,
            "imi": imi,
            "device": device,
            "chain": chain,
        }

    # ========================================================
    # REPLACEMENT
    # ========================================================

    def replace_certificates(
        self,
        mode,
        old_root_cert=None,
        old_root_key=None,
        old_imi_cert=None,
        old_imi_key=None,
    ):
        try:
            replacement_mode = ReplacementMode(
                mode.upper()
            )
        except ValueError:
            raise ValueError(
                f"Invalid replacement mode: {mode}"
            )

        if replacement_mode == ReplacementMode.ALL:
            return self._replace_all(
                old_root_cert,
                old_root_key,
            )

        if replacement_mode == ReplacementMode.IMI_DEVICE:
            return self._replace_imi_device(
                old_root_cert,
                old_root_key,
            )

        if replacement_mode == ReplacementMode.DEVICE:
            return self._replace_device(
                old_root_cert,
                old_root_key,
                old_imi_cert,
                old_imi_key,
            )

        raise RuntimeError(
            "Unsupported replacement mode"
        )

    # ========================================================
    # REPLACE ALL
    # ========================================================

    def _replace_all(
        self,
        old_root_cert,
        old_root_key,
    ):
        print("\n========================================")
        print(" REPLACE ALL")
        print("========================================")

        old_root_cert = self._require_file(
            old_root_cert,
            "Old Root certificate",
        )

        old_root_key = self._require_file(
            old_root_key,
            "Old Root private key",
        )

        replacement_dir = (
            self.output_dir / "replacement"
        )

        root_dir = replacement_dir / "root"
        imi_dir = replacement_dir / "imi"
        device_dir = replacement_dir / "device"

        self._prepare_dir(root_dir)
        self._prepare_dir(imi_dir)
        self._prepare_dir(device_dir)

        # ----------------------------------------------------
        # 1. NEW ROOT
        # ----------------------------------------------------

        print("\n[1/4] Generate NEW ROOT")

        new_root = self._generate_root(
            root_dir
        )

        # ----------------------------------------------------
        # 2. ROOT LINK
        # ----------------------------------------------------

        print("\n[2/4] Generate ROOT LINK")

        root_link = self._generate_root_link(
            old_root_cert=old_root_cert,
            old_root_key=old_root_key,
            new_root_cert=new_root["cert"],
            new_root_key=new_root["key"],
            output_dir=root_dir,
        )

        # ----------------------------------------------------
        # 3. NEW IMI
        # ----------------------------------------------------

        print("\n[3/4] Generate NEW IMI")

        new_imi = self._generate_imi(
            root_cert=new_root["cert"],
            root_key=new_root["key"],
            output_dir=imi_dir,
        )

        # ----------------------------------------------------
        # 4. NEW DEVICE
        # ----------------------------------------------------

        print("\n[4/4] Generate NEW DEVICE")

        new_device = self._generate_device(
            imi_cert=new_imi["cert"],
            imi_key=new_imi["key"],
            output_dir=device_dir,
        )

        # ----------------------------------------------------
        # Verify new chain
        # ----------------------------------------------------

        self._verify_chain(
            root_cert=new_root["cert"],
            imi_cert=new_imi["cert"],
            device_cert=new_device["cert"],
        )

        print("\n[OK] Replace ALL completed.")

        return {
            "mode": "ALL",
            "root": new_root,
            "root_link": root_link,
            "imi": new_imi,
            "device": new_device,
        }

    # ========================================================
    # REPLACE IMI + DEVICE
    # ========================================================

    def _replace_imi_device(
        self,
        old_root_cert,
        old_root_key,
    ):
        print("\n========================================")
        print(" REPLACE IMI + DEVICE")
        print("========================================")

        old_root_cert = self._require_file(
            old_root_cert,
            "Old Root certificate",
        )

        old_root_key = self._require_file(
            old_root_key,
            "Old Root private key",
        )

        replacement_dir = (
            self.output_dir / "replacement"
        )

        imi_dir = replacement_dir / "imi"
        device_dir = replacement_dir / "device"

        self._prepare_dir(imi_dir)
        self._prepare_dir(device_dir)

        # ----------------------------------------------------
        # 1. NEW IMI
        # ----------------------------------------------------

        print("\n[1/2] Generate NEW IMI")

        new_imi = self._generate_imi(
            root_cert=old_root_cert,
            root_key=old_root_key,
            output_dir=imi_dir,
        )

        # ----------------------------------------------------
        # 2. NEW DEVICE
        # ----------------------------------------------------

        print("\n[2/2] Generate NEW DEVICE")

        new_device = self._generate_device(
            imi_cert=new_imi["cert"],
            imi_key=new_imi["key"],
            output_dir=device_dir,
        )

        # ----------------------------------------------------
        # Verify
        # ----------------------------------------------------

        self._verify_chain(
            root_cert=old_root_cert,
            imi_cert=new_imi["cert"],
            device_cert=new_device["cert"],
        )

        print(
            "\n[OK] Replace IMI + Device completed."
        )

        return {
            "mode": "IMI_DEVICE",
            "root": {
                "cert": old_root_cert,
                "key": old_root_key,
            },
            "imi": new_imi,
            "device": new_device,
        }

    # ========================================================
    # REPLACE DEVICE
    # ========================================================

    def _replace_device(
        self,
        old_root_cert,
        old_root_key,
        old_imi_cert,
        old_imi_key,
    ):
        print("\n========================================")
        print(" REPLACE DEVICE")
        print("========================================")

        old_root_cert = self._require_file(
            old_root_cert,
            "Old Root certificate",
        )

        old_root_key = self._require_file(
            old_root_key,
            "Old Root private key",
        )

        old_imi_cert = self._require_file(
            old_imi_cert,
            "Old IMI certificate",
        )

        old_imi_key = self._require_file(
            old_imi_key,
            "Old IMI private key",
        )

        replacement_dir = (
            self.output_dir / "replacement"
        )

        device_dir = replacement_dir / "device"

        self._prepare_dir(device_dir)

        print("\n[1/1] Generate NEW DEVICE")

        new_device = self._generate_device(
            imi_cert=old_imi_cert,
            imi_key=old_imi_key,
            output_dir=device_dir,
        )

        self._verify_chain(
            root_cert=old_root_cert,
            imi_cert=old_imi_cert,
            device_cert=new_device["cert"],
        )

        print(
            "\n[OK] Replace Device completed."
        )

        return {
            "mode": "DEVICE",
            "root": {
                "cert": old_root_cert,
                "key": old_root_key,
            },
            "imi": {
                "cert": old_imi_cert,
                "key": old_imi_key,
            },
            "device": new_device,
        }

    # ========================================================
    # GENERATE ROOT
    # ========================================================

    def _generate_root(self, output_dir):
        output_dir = self._prepare_dir(
            output_dir
        )

        key_file = output_dir / "root.key"
        cert_file = output_dir / "root.crt"

        cfg = self._root_config()

        subject = cfg.get(
            "subject",
            "/C=VN/O=Example/OU=Root CA/CN=Root CA",
        )

        subject = self._format_subject(subject)

        validity_days = cfg.get(
            "validity_days",
            3650,
        )

        # ----------------------------------------------------
        # Generate EC private key
        # ----------------------------------------------------

        self.openssl.run([
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            key_file,
        ])

        # ----------------------------------------------------
        # Self-signed Root CA
        # ----------------------------------------------------

        self.openssl.run([
            "req",
            "-new",
            "-x509",
            "-sha256",
            "-key",
            key_file,
            "-out",
            cert_file,
            "-days",
            validity_days,
            "-subj",
            subject,

            "-addext",
            "basicConstraints=critical,CA:true,pathlen:1",

            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",

            "-addext",
            "subjectKeyIdentifier=hash",
        ])

        # ----------------------------------------------------
        # Convert CRT -> DER
        # ----------------------------------------------------

        der_file = self._convert_crt_to_der(
            cert_file
        )

        return {
            "key": key_file,
            "cert": cert_file,
            "der": der_file,
        }

    # ========================================================
    # GENERATE IMI
    # ========================================================

    def _generate_imi(
        self,
        root_cert,
        root_key,
        output_dir,
    ):
        output_dir = self._prepare_dir(
            output_dir
        )

        root_cert = self._require_file(
            root_cert,
            "Root certificate",
        )

        root_key = self._require_file(
            root_key,
            "Root private key",
        )

        key_file = output_dir / "imi.key"
        csr_file = output_dir / "imi.csr"
        cert_file = output_dir / "imi.crt"
        serial_file = output_dir / "imi.srl"

        cfg = self._imi_config()

        subject = cfg.get(
            "subject",
            "/C=VN/O=Example/OU=IMI/CN=IMI CA",
        )

        subject = self._format_subject(subject)

        validity_days = cfg.get(
            "validity_days",
            3650,
        )

        ext_file = output_dir / "imi_ext.cnf"

        # ----------------------------------------------------
        # Generate key
        # ----------------------------------------------------

        self.openssl.run([
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            key_file,
        ])

        # ----------------------------------------------------
        # CSR
        # ----------------------------------------------------

        self.openssl.run([
            "req",
            "-new",
            "-sha256",
            "-key",
            key_file,
            "-out",
            csr_file,
            "-subj",
            subject,
        ])

        # ----------------------------------------------------
        # IMI extensions
        # ----------------------------------------------------

        self._write_text(
            ext_file,
            """\
[v3_imi]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
""",
        )

        # ----------------------------------------------------
        # Root signs IMI
        # ----------------------------------------------------

        self.openssl.run([
            "x509",
            "-req",
            "-sha256",
            "-in",
            csr_file,
            "-CA",
            root_cert,
            "-CAkey",
            root_key,
            "-CAcreateserial",
            "-CAserial",
            serial_file,
            "-out",
            cert_file,
            "-days",
            validity_days,
            "-extfile",
            ext_file,
            "-extensions",
            "v3_imi",
        ])

        # ----------------------------------------------------
        # Convert CRT -> DER
        # ----------------------------------------------------

        der_file = self._convert_crt_to_der(
            cert_file
        )

        return {
            "key": key_file,
            "csr": csr_file,
            "cert": cert_file,
            "der": der_file,
        }

    # ========================================================
    # GENERATE DEVICE
    # ========================================================

    def _generate_device(
        self,
        imi_cert,
        imi_key,
        output_dir,
    ):
        output_dir = self._prepare_dir(
            output_dir
        )

        imi_cert = self._require_file(
            imi_cert,
            "IMI certificate",
        )

        imi_key = self._require_file(
            imi_key,
            "IMI private key",
        )

        key_file = output_dir / "device.key"
        csr_file = output_dir / "device.csr"
        cert_file = output_dir / "device.crt"
        serial_file = output_dir / "device.srl"

        cfg = self._device_config()

        subject = cfg.get(
            "subject",
            "/C=VN/O=Example/OU=Device/CN=DeviceId",
        )

        subject = self._format_subject(subject)

        validity_days = cfg.get(
            "validity_days",
            3650,
        )

        # ----------------------------------------------------
        # Generate EC P-256 key
        # ----------------------------------------------------

        self.openssl.run([
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            key_file,
        ])

        # ----------------------------------------------------
        # CSR
        # ----------------------------------------------------

        self.openssl.run([
            "req",
            "-new",
            "-sha256",
            "-key",
            key_file,
            "-out",
            csr_file,
            "-subj",
            subject,
        ])

        # ----------------------------------------------------
        # Device extensions
        # ----------------------------------------------------

        ext_file = output_dir / "device_ext.cnf"

        extension_text = self._build_device_extensions()

        self._write_text(
            ext_file,
            extension_text,
        )

        # ----------------------------------------------------
        # IMI signs Device
        # ----------------------------------------------------

        self.openssl.run([
            "x509",
            "-req",
            "-sha256",
            "-in",
            csr_file,
            "-CA",
            imi_cert,
            "-CAkey",
            imi_key,
            "-CAcreateserial",
            "-CAserial",
            serial_file,
            "-out",
            cert_file,
            "-days",
            validity_days,
            "-extfile",
            ext_file,
            "-extensions",
            "v3_device",
        ])

        # ----------------------------------------------------
        # Convert CRT -> DER
        # ----------------------------------------------------

        der_file = self._convert_crt_to_der(
            cert_file
        )

        return {
            "key": key_file,
            "csr": csr_file,
            "cert": cert_file,
            "der": der_file,
        }

    # ========================================================
    # DEVICE EXTENSIONS
    # ========================================================

    def _build_device_extensions(self):
        cfg = self._device_config()

        lines = [
            "[v3_device]",
            "basicConstraints = critical,CA:false",
            "subjectKeyIdentifier = hash",
            "authorityKeyIdentifier = keyid,issuer",
        ]

        # ----------------------------------------------------
        # Key Usage
        # ----------------------------------------------------

        key_usage = cfg.get(
            "key_usage"
        )

        if key_usage:
            value = ",".join(key_usage)

            lines.append(
                f"keyUsage = critical,{value}"
            )

        # ----------------------------------------------------
        # Extended Key Usage
        # ----------------------------------------------------

        eku = cfg.get(
            "extended_key_usage"
        )

        if eku:
            value = ",".join(eku)

            lines.append(
                f"extendedKeyUsage = {value}"
            )

        # ----------------------------------------------------
        # Subject Alternative Name
        # ----------------------------------------------------

        san = cfg.get(
            "subject_alt_name"
        )

        if san:
            lines.append(
                "subjectAltName = @alt_names"
            )

            lines.append("")
            lines.append("[alt_names]")

            index = 1

            for item in san:
                san_type = item["type"]
                san_value = item["value"]

                lines.append(
                    f"{san_type}.{index} = {san_value}"
                )

                index += 1

        # ----------------------------------------------------
        # Specific / Custom extensions
        # ----------------------------------------------------

        specific_extensions = cfg.get(
            "specific_extensions",
            [],
        )

        if specific_extensions:

            for ext in specific_extensions:

                oid = ext["oid"]

                value_type = ext.get(
                    "type",
                    "UTF8String",
                )

                value = ext["value"]

                encoded_value = (
                    self._openssl_extension_value(
                        value_type,
                        value,
                    )
                )

                critical = ext.get(
                    "critical",
                    False,
                )

                if critical:
                    lines.append(
                        f"{oid} = critical,{encoded_value}"
                    )
                else:
                    lines.append(
                        f"{oid} = {encoded_value}"
                    )

        lines.append("")

        return "\n".join(lines)

    # ========================================================
    # Custom extension value encoder
    # ========================================================

    @staticmethod
    def _openssl_extension_value(
        value_type,
        value,
    ):
        value_type = value_type.upper()

        if value_type == "UTF8STRING":
            return f"ASN1:UTF8String:{value}"

        if value_type == "IA5STRING":
            return f"ASN1:IA5STRING:{value}"

        if value_type == "PRINTABLESTRING":
            return f"ASN1:PRINTABLESTRING:{value}"

        if value_type == "INTEGER":
            return f"ASN1:INTEGER:{value}"

        if value_type == "BOOLEAN":
            return f"ASN1:BOOLEAN:{value}"

        if value_type == "HEX":
            return f"DER:HEX:{value}"

        if value_type == "DER":
            return f"DER:{value}"

        raise ValueError(
            f"Unsupported extension type: {value_type}"
        )

    # ========================================================
    # ROOT LINK
    # ========================================================

    def _generate_root_link(
        self,
        old_root_cert,
        old_root_key,
        new_root_cert,
        new_root_key,
        output_dir,
    ):
        """
        Generate Root Link.

        OLD ROOT private key signs ROOT LINK.

        ROOT LINK public key == NEW ROOT public key.
        """

        output_dir = self._prepare_dir(
            output_dir
        )

        old_root_cert = self._require_file(
            old_root_cert,
            "Old Root certificate",
        )

        old_root_key = self._require_file(
            old_root_key,
            "Old Root private key",
        )

        new_root_cert = self._require_file(
            new_root_cert,
            "New Root certificate",
        )

        new_root_key = self._require_file(
            new_root_key,
            "New Root private key",
        )

        csr_file = output_dir / "root-link.csr"
        cert_file = output_dir / "root-link.crt"
        serial_file = output_dir / "root-link.srl"
        ext_file = output_dir / "root_link_ext.cnf"

        cfg = self._root_config()

        validity_days = cfg.get(
            "validity_days",
            3650,
        )

        # ----------------------------------------------------
        # Create CSR using NEW ROOT key
        # ----------------------------------------------------

        self.openssl.run([
            "req",
            "-new",
            "-sha256",
            "-key",
            new_root_key,
            "-out",
            csr_file,
            "-subj",
            "/C=VN/O=Example/OU=Root Link/CN=Root Link",
        ])

        self._write_text(
            ext_file,
            """\
[v3_root_link]
basicConstraints = critical,CA:true,pathlen:1
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
""",
        )

        # ----------------------------------------------------
        # OLD ROOT signs Root Link
        # ----------------------------------------------------

        self.openssl.run([
            "x509",
            "-req",
            "-sha256",
            "-in",
            csr_file,
            "-CA",
            old_root_cert,
            "-CAkey",
            old_root_key,
            "-CAcreateserial",
            "-CAserial",
            serial_file,
            "-out",
            cert_file,
            "-days",
            validity_days,
            "-extfile",
            ext_file,
            "-extensions",
            "v3_root_link",
        ])

        # ----------------------------------------------------
        # Verify Root Link public key == New Root public key
        # ----------------------------------------------------

        self._verify_same_public_key(
            cert1=cert_file,
            cert2=new_root_cert,
        )

        # ----------------------------------------------------
        # Convert CRT -> DER
        # ----------------------------------------------------

        der_file = self._convert_crt_to_der(
            cert_file
        )

        return {
            "cert": cert_file,
            "der": der_file,
            "csr": csr_file,
        }

    # ========================================================
    # Chain
    # ========================================================

    def _create_chain(
        self,
        root_cert,
        imi_cert,
        device_cert,
        output_dir,
    ):
        output_dir = self._prepare_dir(
            output_dir
        )

        chain_file = (
            output_dir / "device-chain.pem"
        )

        content = (
            Path(device_cert).read_text()
            + Path(imi_cert).read_text()
            + Path(root_cert).read_text()
        )

        chain_file.write_text(
            content,
            encoding="utf-8",
        )

        return chain_file

    # ========================================================
    # Verify X.509 chain
    # ========================================================

    def _verify_chain(
        self,
        root_cert,
        imi_cert,
        device_cert,
    ):
        print("\n[VERIFY] Certificate chain")

        root_cert = self._require_file(
            root_cert,
            "Root certificate",
        )

        imi_cert = self._require_file(
            imi_cert,
            "IMI certificate",
        )

        device_cert = self._require_file(
            device_cert,
            "Device certificate",
        )

        result = self.openssl.run([
            "verify",
            "-CAfile",
            root_cert,
            "-untrusted",
            imi_cert,
            device_cert,
        ])

        print(
            f"[VERIFY] {result.stdout.strip()}"
        )

    # ========================================================
    # Verify same public key
    # ========================================================

    def _verify_same_public_key(
        self,
        cert1,
        cert2,
    ):
        tmp1 = (
            self.output_dir /
            ".root_link_pubkey.pem"
        )

        tmp2 = (
            self.output_dir /
            ".new_root_pubkey.pem"
        )

        try:
            self.openssl.run([
                "x509",
                "-in",
                cert1,
                "-pubkey",
                "-noout",
                "-out",
                tmp1,
            ])

            self.openssl.run([
                "x509",
                "-in",
                cert2,
                "-pubkey",
                "-noout",
                "-out",
                tmp2,
            ])

            key1 = tmp1.read_text(
                encoding="utf-8"
            ).strip()

            key2 = tmp2.read_text(
                encoding="utf-8"
            ).strip()

            if key1 != key2:
                raise RuntimeError(
                    "Root Link public key does NOT match "
                    "New Root public key."
                )

            print(
                "[VERIFY] Root Link public key == "
                "New Root public key"
            )

        finally:
            self._remove_file(tmp1)
            self._remove_file(tmp2)


# ============================================================
# JSON
# ============================================================

def load_config(path):
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {path}"
        )

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


# ============================================================
# CLI
# ============================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "ECDSA P-256 X.509 Certificate Generator"
        )
    )

    parser.add_argument(
        "mode",
        choices=[
            "generate",
            "replace-all",
            "replace-imi-device",
            "replace-device",
        ],
        help="Certificate operation mode",
    )

    parser.add_argument(
        "-c",
        "--config",
        default="input.json",
        help="Configuration JSON file",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="output",
        help="Output directory",
    )

    parser.add_argument(
        "--openssl",
        default=None,
        help="Path to openssl.exe",
    )

    parser.add_argument(
        "--old-root-cert",
        default=None,
        help="Old Root certificate",
    )

    parser.add_argument(
        "--old-root-key",
        default=None,
        help="Old Root private key",
    )

    parser.add_argument(
        "--old-imi-cert",
        default=None,
        help="Old IMI certificate",
    )

    parser.add_argument(
        "--old-imi-key",
        default=None,
        help="Old IMI private key",
    )

    return parser.parse_args()


# ============================================================
# Validate CLI arguments
# ============================================================

def validate_arguments(args):
    if args.mode == "generate":
        return

    if not args.old_root_cert:
        raise ValueError(
            f"{args.mode} requires --old-root-cert"
        )

    if not args.old_root_key:
        raise ValueError(
            f"{args.mode} requires --old-root-key"
        )

    if args.mode == "replace-device":

        if not args.old_imi_cert:
            raise ValueError(
                "replace-device requires --old-imi-cert"
            )

        if not args.old_imi_key:
            raise ValueError(
                "replace-device requires --old-imi-key"
            )


# ============================================================
# Main
# ============================================================

def main():
    args = parse_args()

    validate_arguments(args)

    config = load_config(
        args.config
    )

    # --------------------------------------------------------
    # OpenSSL priority:
    #
    # 1. CLI
    # 2. input.json
    # 3. PATH
    # --------------------------------------------------------

    openssl_path = (
        args.openssl
        or config.get(
            "openssl",
            {}
        ).get(
            "path"
        )
        or "openssl"
    )

    generator = CertificateGenerator(
        config=config,
        output_dir=args.output,
        openssl_path=openssl_path,
    )

    # --------------------------------------------------------
    # Execute
    # --------------------------------------------------------

    if args.mode == "generate":

        generator.generate()

    else:

        generator.replace_certificates(
            mode={
                "replace-all": "ALL",
                "replace-imi-device": "IMI_DEVICE",
                "replace-device": "DEVICE",
            }[args.mode],

            old_root_cert=args.old_root_cert,
            old_root_key=args.old_root_key,

            old_imi_cert=args.old_imi_cert,
            old_imi_key=args.old_imi_key,
        )


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":
    try:
        main()

    except Exception as exc:
        print(
            f"\n[ERROR] {exc}",
            file=sys.stderr,
        )
        sys.exit(1)
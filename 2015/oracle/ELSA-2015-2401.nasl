# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122752");
  script_cve_id("CVE-2015-5281");
  script_tag(name:"creation_date", value:"2015-11-24 08:17:26 +0000 (Tue, 24 Nov 2015)");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2015-2401)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2401");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2401.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grub2' package(s) announced via the ELSA-2015-2401 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.02-0.29.0.1]
- Fix comparison in patch for 18504756
- Remove symlink to grub environment file during uninstall on EFI platforms
 [bug 19231481]
- update Oracle Linux certificates (Alexey Petrenko)
- Put 'with' in menuentry instead of 'using' [bug 18504756]
- Use different titles for UEK and RHCK kernels [bug 18504756]

[2.02-0.29]
- Fix DHCP6 timeouts due to failed network stack once more.
 Resolves: rhbz#1267139

[2.02-0.28]
- Once again, rebuild for the right build target.
 Resolves: CVE-2015-5281

[2.02-0.27]
- Remove multiboot and multiboot2 modules from the .efi builds, they
 should never have been there.
 Resolves: CVE-2015-5281

[2.02-0.26]
- Be more aggressive about trying to make sure we use the configured SNP
 device in UEFI.
 Resolves: rhbz#1257475

[2.02-0.25]
- Force file sync to disk on ppc64le machines.
 Resolves: rhbz#1212114

[2.02-0.24]
- Undo 0.23 and fix it a different way.
 Resolves: rhbz#1124074

[2.02-0.23]
- Reverse kernel sort order so they're displayed correctly.
 Resolves: rhbz#1124074

[2.02-0.22]
- Make upgrades work reasonably well with grub2-setpassword.
 Related: rhbz#985962

[2.02-0.21]
- Add a simpler grub2 password config tool
 Related: rhbz#985962
- Some more coverity nits.

[2.02-0.20]
- Deal with some coverity nits.
 Related: rhbz#1215839
 Related: rhbz#1124074

[2.02-0.19]
- Rebuild for Aarch64
- Deal with some coverity nits.
 Related: rhbz#1215839
 Related: rhbz#1124074

[2.02-0.18]
- Update for an rpmdiff problem with one of the man pages.
 Related: rhbz#1124074");

  script_tag(name:"affected", value:"'grub2' package(s) on Oracle Linux 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"grub2", rpm:"grub2~2.02~0.29.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi", rpm:"grub2-efi~2.02~0.29.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-modules", rpm:"grub2-efi-modules~2.02~0.29.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools", rpm:"grub2-tools~2.02~0.29.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);

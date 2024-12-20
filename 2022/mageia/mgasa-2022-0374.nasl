# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0374");
  script_cve_id("CVE-2022-2928", "CVE-2022-2929");
  script_tag(name:"creation_date", value:"2022-10-19 04:46:32 +0000 (Wed, 19 Oct 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-13 13:33:13 +0000 (Thu, 13 Oct 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0374)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0374");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0374.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30942");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2022-2928");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2022-2929");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5658-1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/10/05/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dhcp' package(s) announced via the MGASA-2022-0374 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In ISC DHCP 4.4.0 -> 4.4.3, ISC DHCP 4.1-ESV-R1 -> 4.1-ESV-R16-P1, when
the function option_code_hash_lookup() is called from add_option(), it
increases the option's refcount field. However, there is not a
corresponding call to option_dereference() to decrement the refcount
field. The function add_option() is only used in server responses to
lease query packets. Each lease query response calls this function for
several options, so eventually, the reference counters could overflow and
cause the server to abort. (CVE-2022-2928)

In ISC DHCP 1.0 -> 4.4.3, ISC DHCP 4.1-ESV-R1 -> 4.1-ESV-R16-P1 a system
with access to a DHCP server, sending DHCP packets crafted to include fqdn
labels longer than 63 bytes, could eventually cause the server to run out
of memory. (CVE-2022-2929)");

  script_tag(name:"affected", value:"'dhcp' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"dhcp", rpm:"dhcp~4.4.2~10.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-client", rpm:"dhcp-client~4.4.2~10.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-common", rpm:"dhcp-common~4.4.2~10.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-devel", rpm:"dhcp-devel~4.4.2~10.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-doc", rpm:"dhcp-doc~4.4.2~10.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-relay", rpm:"dhcp-relay~4.4.2~10.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-server", rpm:"dhcp-server~4.4.2~10.2.mga8", rls:"MAGEIA8"))) {
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

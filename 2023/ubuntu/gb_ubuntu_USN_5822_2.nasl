# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5822.2");
  script_cve_id("CVE-2021-20251", "CVE-2022-3437", "CVE-2022-37966", "CVE-2022-37967", "CVE-2022-38023", "CVE-2022-42898", "CVE-2022-45141");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-13 18:05:10 +0000 (Mon, 13 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-5822-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5822-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5822-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2003867");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2003891");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2022-37966.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2022-37967.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2022-38023.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the USN-5822-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5822-1 fixed vulnerabilities in Samba. The update for Ubuntu 20.04 LTS
introduced regressions in certain environments. Pending investigation of
these regressions, this update temporarily reverts the security fixes.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that Samba incorrectly handled the bad password count
 logic. A remote attacker could possibly use this issue to bypass bad
 passwords lockouts. This issue was only addressed in Ubuntu 22.10.
 (CVE-2021-20251)

 Evgeny Legerov discovered that Samba incorrectly handled buffers in
 certain GSSAPI routines of Heimdal. A remote attacker could possibly use
 this issue to cause Samba to crash, resulting in a denial of service.
 (CVE-2022-3437)

 Tom Tervoort discovered that Samba incorrectly used weak rc4-hmac Kerberos
 keys. A remote attacker could possibly use this issue to elevate
 privileges. (CVE-2022-37966, CVE-2022-37967)

 It was discovered that Samba supported weak RC4/HMAC-MD5 in NetLogon Secure
 Channel. A remote attacker could possibly use this issue to elevate
 privileges. (CVE-2022-38023)

 Greg Hudson discovered that Samba incorrectly handled PAC parsing. On
 32-bit systems, a remote attacker could use this issue to escalate
 privileges, or possibly execute arbitrary code. (CVE-2022-42898)

 Joseph Sutton discovered that Samba could be forced to issue rc4-hmac
 encrypted Kerberos tickets. A remote attacker could possibly use this issue
 to escalate privileges. This issue only affected Ubuntu 20.04 LTS and
 Ubuntu 22.04 LTS. (CVE-2022-45141)

 WARNING: The fixes included in these updates introduce several important
 behavior changes which may cause compatibility problems interacting with
 systems still expecting the former behavior. Please see the following
 upstream advisories for more information:

 [link moved to references]
 [link moved to references]
 [link moved to references]");

  script_tag(name:"affected", value:"'samba' package(s) on Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:4.13.17~dfsg-0ubuntu1.20.04.5", rls:"UBUNTU20.04 LTS"))) {
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

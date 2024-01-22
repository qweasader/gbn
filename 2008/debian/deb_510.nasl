# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53200");
  script_cve_id("CVE-2004-0448");
  script_tag(name:"creation_date", value:"2008-01-17 21:45:44 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-510)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-510");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/DSA-510");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-510");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jftpgw' package(s) announced via the DSA-510 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"jaguar@felinemenace.org discovered a vulnerability in jftpgw, an FTP proxy program, whereby a remote user could potentially cause arbitrary code to be executed with the privileges of the jftpgw server process. By default, the server runs as user 'nobody'.

CAN-2004-0448: format string vulnerability via syslog(3) in log() function

For the current stable distribution (woody) this problem has been fixed in version 0.13.1-1woody1.

For the unstable distribution (sid), this problem has been fixed in version 0.13.4-1.

We recommend that you update your jftpgw package.");

  script_tag(name:"affected", value:"'jftpgw' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"jftpgw", ver:"0.13.1-1woody1", rls:"DEB3.0"))) {
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

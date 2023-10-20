# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.217");
  script_cve_id("CVE-2014-9622", "CVE-2015-1877");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 14:01:00 +0000 (Mon, 14 Jun 2021)");

  script_name("Debian: Security Advisory (DLA-217)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-217");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-217");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xdg-utils' package(s) announced via the DLA-217 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The two below CVE issues have recently been fixed in Debian squeeze-lts:

CVE-2014-9622

John Houwer discovered a way to cause xdg-open, a tool that automatically opens URLs in a user's preferred application, to execute arbitrary commands remotely.

CVE-2015-1877

Jiri Horner discovered a way to cause xdg-open, a tool that automatically opens URLs in a user's preferred application, to execute arbitrary commands remotely.

This problem only affects /bin/sh implementations that don't sanitize local variables. Dash, which is the default /bin/sh in Debian is affected. Bash as /bin/sh is known to be unaffected.");

  script_tag(name:"affected", value:"'xdg-utils' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"xdg-utils", ver:"1.0.2+cvs20100307-2+deb6u1", rls:"DEB6"))) {
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

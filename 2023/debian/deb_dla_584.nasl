# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.584");
  script_cve_id("CVE-2016-1238");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-01-12T16:12:12+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:12 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-22 16:58:00 +0000 (Fri, 22 Sep 2023)");

  script_name("Debian: Security Advisory (DLA-584-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-584-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/DLA-584-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libsys-syslog-perl' package(s) announced via the DLA-584-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"John Lightsey and Todd Rinaldo reported that the opportunistic loading of optional modules can make many programs unintentionally load code from the current working directory (which might be changed to another directory without the user realising) and potentially leading to privilege escalation, as demonstrated in Debian with certain combinations of installed packages.

The problem relates to Perl loading modules from the includes directory array ('@INC') in which the last element is the current directory ('.'). That means that, when perl wants to load a module (during first compilation or during lazy loading of a module in run time), perl will look for the module in the current directory at the end, since '.' is the last include directory in its array of include directories to seek. The issue is with requiring libraries that are in '.' but are not otherwise installed.

With this update the Sys::Syslog Perl module is updated to not load modules from current directory.

For Debian 7 Wheezy, these problems have been fixed in version 0.29-1+deb7u1.

We recommend that you upgrade your libsys-syslog-perl packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libsys-syslog-perl' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libsys-syslog-perl", ver:"0.29-1+deb7u1", rls:"DEB7"))) {
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

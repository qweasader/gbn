# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703462");
  script_cve_id("CVE-2015-8747", "CVE-2015-8748");
  script_tag(name:"creation_date", value:"2016-01-29 23:00:00 +0000 (Fri, 29 Jan 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-02-16 18:17:55 +0000 (Tue, 16 Feb 2016)");

  script_name("Debian: Security Advisory (DSA-3462-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3462-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3462-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3462");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'radicale' package(s) announced via the DSA-3462-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were fixed in radicale, a CardDAV/CalDAV server.

CVE-2015-8747

The (not configured by default and not available on Wheezy) multifilesystem storage backend allows read and write access to arbitrary files (still subject to the DAC permissions of the user the radicale server is running as).

CVE-2015-8748

If an attacker is able to authenticate with a user name like `.*', he can bypass read/write limitations imposed by regex-based rules, including the built-in rules `owner_write' (read for everybody, write for the calendar owner) and `owner_only' (read and write for the calendar owner).

For the oldstable distribution (wheezy), these problems have been fixed in version 0.7-1.1+deb7u1.

For the stable distribution (jessie), these problems have been fixed in version 0.9-1+deb8u1.

For the testing distribution (stretch), these problems have been fixed in version 1.1.1-1.

For the unstable distribution (sid), these problems have been fixed in version 1.1.1-1.

We recommend that you upgrade your radicale packages.");

  script_tag(name:"affected", value:"'radicale' package(s) on Debian 7, Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-radicale", ver:"0.7-1.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"radicale", ver:"0.7-1.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"python-radicale", ver:"0.9-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"radicale", ver:"0.9-1+deb8u1", rls:"DEB8"))) {
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

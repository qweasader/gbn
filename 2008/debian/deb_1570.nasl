# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60938");
  script_cve_id("CVE-2006-7227", "CVE-2006-7228", "CVE-2006-7230", "CVE-2007-1659", "CVE-2007-1660", "CVE-2007-1661", "CVE-2007-1662", "CVE-2007-4766", "CVE-2007-4767", "CVE-2007-4768");
  script_tag(name:"creation_date", value:"2008-05-12 17:53:28 +0000 (Mon, 12 May 2008)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1570-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1570-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1570-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1570");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kazehakase' package(s) announced via the DSA-1570-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andrews Salomon reported that kazehakase, a GTK+-based web browser that allows pluggable rendering engines, contained an embedded copy of the PCRE library in its source tree which was compiled in and used in preference to the system-wide version of this library.

The PCRE library has been updated to fix the security issues reported against it in previous Debian Security Advisories. This update ensures that kazehakase uses that supported library, and not its own embedded and insecure version.

For the stable distribution (etch), this problem has been fixed in version 0.4.2-1etch1.

We recommend that you upgrade your kazehakase package.");

  script_tag(name:"affected", value:"'kazehakase' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"kazehakase", ver:"0.4.2-1etch1", rls:"DEB4"))) {
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

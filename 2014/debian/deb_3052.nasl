# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703052");
  script_cve_id("CVE-2014-3686");
  script_tag(name:"creation_date", value:"2014-10-14 22:00:00 +0000 (Tue, 14 Oct 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3052-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3052-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-3052-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3052");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wpa' package(s) announced via the DSA-3052-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jouni Malinen discovered an input sanitization issue in the wpa_cli and hostapd_cli tools included in the wpa package. A remote wifi system within range could provide a crafted string triggering arbitrary code execution running with privileges of the affected wpa_cli or hostapd_cli process.

For the stable distribution (wheezy), this problem has been fixed in version 1.0-3+deb7u1.

For the testing distribution (jessie), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 2.3-1.

We recommend that you upgrade your wpa packages.");

  script_tag(name:"affected", value:"'wpa' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"hostapd", ver:"1:1.0-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpagui", ver:"1.0-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant", ver:"1.0-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant-udeb", ver:"1.0-3+deb7u1", rls:"DEB7"))) {
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

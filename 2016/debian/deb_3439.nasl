# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703439");
  script_cve_id("CVE-2016-1231", "CVE-2016-1232");
  script_tag(name:"creation_date", value:"2016-01-09 23:00:00 +0000 (Sat, 09 Jan 2016)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-09 11:39:00 +0000 (Thu, 09 Jun 2016)");

  script_name("Debian: Security Advisory (DSA-3439-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3439-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3439-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3439");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'prosody' package(s) announced via the DSA-3439-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in Prosody, a lightweight Jabber/XMPP server. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2016-1231

Kim Alvefur discovered a flaw in Prosody's HTTP file-serving module that allows it to serve requests outside of the configured public root directory. A remote attacker can exploit this flaw to access private files including sensitive data. The default configuration does not enable the mod_http_files module and thus is not vulnerable.

CVE-2016-1232

Thijs Alkemade discovered that Prosody's generation of the secret token for server-to-server dialback authentication relied upon a weak random number generator that was not cryptographically secure. A remote attacker can take advantage of this flaw to guess at probable values of the secret key and impersonate the affected domain to other servers on the network.

For the oldstable distribution (wheezy), these problems have been fixed in version 0.8.2-4+deb7u3.

For the stable distribution (jessie), these problems have been fixed in version 0.9.7-2+deb8u2.

We recommend that you upgrade your prosody packages.");

  script_tag(name:"affected", value:"'prosody' package(s) on Debian 7, Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"prosody", ver:"0.8.2-4+deb7u3", rls:"DEB7"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"prosody", ver:"0.9.7-2+deb8u2", rls:"DEB8"))) {
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

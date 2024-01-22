# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53455");
  script_cve_id("CVE-2002-1365");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-216)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-216");
  script_xref(name:"URL", value:"https://www.debian.org/security/2002/DSA-216");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-216");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fetchmail' package(s) announced via the DSA-216 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stefan Esser of e-matters discovered a buffer overflow in fetchmail, an SSL enabled POP3, APOP and IMAP mail gatherer/forwarder. When fetchmail retrieves a mail all headers that contain addresses are searched for local addresses. If a hostname is missing, fetchmail appends it but doesn't reserve enough space for it. This heap overflow can be used by remote attackers to crash it or to execute arbitrary code with the privileges of the user running fetchmail.

For the current stable distribution (woody) this problem has been fixed in version 5.9.11-6.2 of fetchmail and fetchmail-ssl.

For the old stable distribution (potato) this problem has been fixed in version 5.3.3-4.3.

For the unstable distribution (sid) this problem has been fixed in version 6.2.0-1 of fetchmail and fetchmail-ssl.

We recommend that you upgrade your fetchmail packages.");

  script_tag(name:"affected", value:"'fetchmail' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"fetchmail", ver:"5.9.11-6.2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fetchmail-common", ver:"5.9.11-6.2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fetchmailconf", ver:"5.9.11-6.2", rls:"DEB3.0"))) {
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

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703655");
  script_cve_id("CVE-2016-6265", "CVE-2016-6525");
  script_tag(name:"creation_date", value:"2016-08-25 22:00:00 +0000 (Thu, 25 Aug 2016)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:30:00 +0000 (Sat, 01 Jul 2017)");

  script_name("Debian: Security Advisory (DSA-3655-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3655-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3655-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3655");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mupdf' package(s) announced via the DSA-3655-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in MuPDF, a lightweight PDF viewer. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2016-6265

Marco Grassi discovered a use-after-free vulnerability in MuPDF. An attacker can take advantage of this flaw to cause an application crash (denial-of-service), or potentially to execute arbitrary code with the privileges of the user running MuPDF, if a specially crafted PDF file is processed.

CVE-2016-6525

Yu Hong and Zheng Jihong discovered a heap overflow vulnerability within the pdf_load_mesh_params function, allowing an attacker to cause an application crash (denial-of-service), or potentially to execute arbitrary code with the privileges of the user running MuPDF, if a specially crafted PDF file is processed.

For the stable distribution (jessie), these problems have been fixed in version 1.5-1+deb8u1.

We recommend that you upgrade your mupdf packages.");

  script_tag(name:"affected", value:"'mupdf' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libmupdf-dev", ver:"1.5-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mupdf", ver:"1.5-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mupdf-tools", ver:"1.5-1+deb8u1", rls:"DEB8"))) {
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

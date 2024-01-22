# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704604");
  script_cve_id("CVE-2019-17358");
  script_tag(name:"creation_date", value:"2020-01-21 04:00:50 +0000 (Tue, 21 Jan 2020)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4604-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4604-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4604-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4604");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/cacti");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cacti' package(s) announced via the DSA-4604-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues have been found in cacti, a server monitoring system, potentially resulting in SQL code execution or information disclosure by authenticated users.

CVE-2019-16723

Authenticated users may bypass authorization checks for viewing a graph by submitting requests with modified local_graph_id parameters.

CVE-2019-17357

The graph administration interface insufficiently sanitizes the template_id parameter, potentially resulting in SQL injection. This vulnerability might be leveraged by authenticated attackers to perform unauthorized SQL code execution on the database.

CVE-2019-17358

The sanitize_unserialize_selected_items function (lib/functions.php) insufficiently sanitizes user input before deserializing it, potentially resulting in unsafe deserialization of user-controlled data. This vulnerability might be leveraged by authenticated attackers to influence the program control flow or cause memory corruption.

For the oldstable distribution (stretch), these problems have been fixed in version 0.8.8h+ds1-10+deb9u1. Note that stretch was only affected by CVE-2018-17358.

For the stable distribution (buster), these problems have been fixed in version 1.2.2+ds1-2+deb10u2.

We recommend that you upgrade your cacti packages.

For the detailed security status of cacti please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'cacti' package(s) on Debian 9, Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"cacti", ver:"1.2.2+ds1-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"cacti", ver:"0.8.8h+ds1-10+deb9u1", rls:"DEB9"))) {
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

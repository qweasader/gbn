# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.142");
  script_cve_id("CVE-2015-1031", "CVE-2015-1381", "CVE-2015-1382");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DLA-142-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-142-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/DLA-142-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'privoxy' package(s) announced via the DLA-142-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been fixed in privoxy, a privacy enhancing HTTP proxy:

CVE-2015-1031, CID66394 unmap(): Prevent use-after-free if the map only consists of one item.

CVE-2015-1031, CID66376 and CID66391 pcrs_execute(): Consistently set *result to NULL in case of errors. Should make use-after-free in the caller less likely.

CVE-2015-1381

Fix multiple segmentation faults and memory leaks in the pcrs code.

CVE-2015-1382

Fix invalid read to prevent potential crashes.

We recommend that you upgrade your privoxy packages.

For Debian 6 Squeeze, these issues have been fixed in privoxy version 3.0.16-1+deb6u1");

  script_tag(name:"affected", value:"'privoxy' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"privoxy", ver:"3.0.16-1+deb6u1", rls:"DEB6"))) {
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

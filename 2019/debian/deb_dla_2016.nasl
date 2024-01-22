# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892016");
  script_cve_id("CVE-2018-20020", "CVE-2018-20021", "CVE-2018-20022", "CVE-2018-20024");
  script_tag(name:"creation_date", value:"2019-11-30 03:00:14 +0000 (Sat, 30 Nov 2019)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-23 13:15:00 +0000 (Fri, 23 Oct 2020)");

  script_name("Debian: Security Advisory (DLA-2016-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-2016-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-2016-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ssvnc' package(s) announced via the DLA-2016-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been identified in the VNC code of ssvnc, an encryption-capable VNC client..

The vulnerabilities referenced below are issues that have originally been reported against Debian source package libvncserver (which also ships the libvncclient shared library). The ssvnc source package in Debian ships a custom-patched, stripped down and outdated variant of libvncclient, thus some of libvncclient's security fixes required porting over.

CVE-2018-20020

LibVNC contained heap out-of-bound write vulnerability inside structure in VNC client code that can result remote code execution

CVE-2018-20021

LibVNC contained a CWE-835: Infinite loop vulnerability in VNC client code. Vulnerability allows attacker to consume excessive amount of resources like CPU and RAM

CVE-2018-20022

LibVNC contained multiple weaknesses CWE-665: Improper Initialization vulnerability in VNC client code that allowed attackers to read stack memory and could be abused for information disclosure. Combined with another vulnerability, it could be used to leak stack memory layout and in bypassing ASLR.

CVE-2018-20024

LibVNC contained null pointer dereference in VNC client code that could result DoS.

For Debian 8 Jessie, these problems have been fixed in version 1.0.29-2+deb8u1.

We recommend that you upgrade your ssvnc packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ssvnc' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ssvnc", ver:"1.0.29-2+deb8u1", rls:"DEB8"))) {
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

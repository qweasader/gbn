# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/fedora-package-announce/2008-October/msg00259.html");
  script_oid("1.3.6.1.4.1.25623.1.0.860460");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-17 17:05:11 +0100 (Tue, 17 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"FEDORA", value:"2008-8738");
  script_cve_id("CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3905", "CVE-2008-3790", "CVE-2008-3443", "CVE-2008-1447", "CVE-2008-1891", "CVE-2008-2662", "CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726", "CVE-2007-5162");
  script_name("Fedora Update for ruby FEDORA-2008-8738");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC9");
  script_tag(name:"affected", value:"ruby on Fedora 9");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC9")
{

  if ((res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.8.6.287~2.fc9", rls:"FC9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
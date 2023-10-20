# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2010-February/035070.html");
  script_oid("1.3.6.1.4.1.25623.1.0.861742");
  script_version("2023-06-30T05:06:12+0000");
  script_tag(name:"last_modification", value:"2023-06-30 05:06:12 +0000 (Fri, 30 Jun 2023)");
  script_tag(name:"creation_date", value:"2010-03-02 08:38:02 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"FEDORA", value:"2010-1804");
  script_cve_id("CVE-2010-0410", "CVE-2010-0415", "CVE-2010-0307", "CVE-2009-4537", "CVE-2009-4536", "CVE-2009-4538", "CVE-2009-4141", "CVE-2010-0003", "CVE-2010-0007", "CVE-2010-0006", "CVE-2009-3547", "CVE-2009-3638", "CVE-2009-3624", "CVE-2009-3621", "CVE-2009-3620", "CVE-2009-3612", "CVE-2009-2909", "CVE-2009-2908", "CVE-2009-2903", "CVE-2009-3290", "CVE-2009-2847");
  script_name("Fedora Update for kernel FEDORA-2010-1804");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC11");
  script_tag(name:"affected", value:"kernel on Fedora 11");
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

if(release == "FC11")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.30.10~105.2.23.fc11", rls:"FC11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
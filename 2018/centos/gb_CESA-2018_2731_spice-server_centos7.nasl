# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882950");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-10-03 17:02:01 +0530 (Wed, 03 Oct 2018)");
  script_cve_id("CVE-2018-10873");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:33:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for spice-server CESA-2018:2731 centos7");
  script_tag(name:"summary", value:"Check the version of spice-server");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"The Simple Protocol for Independent Computing
  Environments (SPICE) is a remote display system built for virtual environments
  which allows the user to view a computing 'desktop' environment not only on the
  machine where it is running, but from anywhere on the Internet and from a wide
  variety of machine architectures.

The spice-gtk packages provide a GIMP Toolkit (GTK+) widget for Simple
Protocol for Independent Computing Environments (SPICE) clients. Both
Virtual Machine Manager and Virtual Machine Viewer can make use of this
widget to access virtual machines using the SPICE protocol.

Security Fix(es):

  * spice: Missing check in demarshal.py:write_validate_array_item() allows
for buffer overflow and denial of service (CVE-2018-10873)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

This issue was discovered by Frediano Ziglio (Red Hat).");
  script_tag(name:"affected", value:"spice-server on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"CESA", value:"2018:2731");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-September/023047.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"spice-server", rpm:"spice-server~0.14.0~2.el7_5.5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-server-devel", rpm:"spice-server-devel~0.14.0~2.el7_5.5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice", rpm:"spice~0.14.0~2.el7_5.5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-01/msg00012.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831311");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-21 14:59:01 +0100 (Fri, 21 Jan 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"MDVSA", value:"2011:010");
  script_cve_id("CVE-2009-4227", "CVE-2009-4228", "CVE-2010-4262");
  script_name("Mandriva Update for xfig MDVSA-2011:010 (xfig)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xfig'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(2010\.1|2010\.0|2009\.0)");
  script_tag(name:"affected", value:"xfig on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in xfig:

  Stack-based buffer overflow in the read_1_3_textobject function in
  f_readold.c in Xfig 3.2.5b and earlier, and in the read_textobject
  function in read1_3.c in fig2dev in Transfig 3.2.5a and earlier,
  allows remote attackers to execute arbitrary code via a long string
  in a malformed .fig file that uses the 1.3 file format.  NOTE:
  some of these details are obtained from third party information
  (CVE-2009-4227).

  Stack consumption vulnerability in u_bound.c in Xfig 3.2.5b and earlier
  allows remote attackers to cause a denial of service (application
  crash) via a long string in a malformed .fig file that uses the 1.3
  file format, possibly related to the readfp_fig function in f_read.c
  (CVE-2009-4228).

  Stack-based buffer overflow in Xfig 3.2.4 and 3.2.5 allows remote
  attackers to cause a denial of service (crash) and possibly execute
  arbitrary code via a FIG image with a crafted color definition
  (CVE-2010-4262).

  Packages for 2009.0 are provided as of the Extended Maintenance
  Program. The updated packages have been patched to correct these issues.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://store.mandriva.com/product_info.php?cPath=149&amp;amp;products_id=490");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"xfig", rpm:"xfig~3.2.5b~3.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"xfig", rpm:"xfig~3.2.5b~1.3mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"xfig", rpm:"xfig~3.2.5~4.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

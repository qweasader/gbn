# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-10/msg00001.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831456");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"MDVSA", value:"2011:140");
  script_cve_id("CVE-2011-2996", "CVE-2011-2995", "CVE-2011-2999", "CVE-2011-2998", "CVE-2011-3000", "CVE-2011-3001", "CVE-2010-0170", "CVE-2011-2372");
  script_name("Mandriva Update for mozilla-thunderbird MDVSA-2011:140 (mozilla-thunderbird)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(2010\.1|2009\.0)");
  script_tag(name:"affected", value:"mozilla-thunderbird on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64");
  script_tag(name:"insight", value:"Security issues were identified and fixed in mozilla firefox and
  thunderbird:

  Mozilla Firefox before 3.6.23 and 4.x through 6, Thunderbird before
  7.0, and SeaMonkey before 2.4 do not prevent the starting of a download
  in response to the holding of the Enter key, which allows user-assisted
  remote attackers to bypass intended access restrictions via a crafted
  web site (CVE-2011-2372).

  Multiple unspecified vulnerabilities in the browser engine in Mozilla
  Firefox before 3.6.23 and 4.x through 6, Thunderbird before 7.0,
  and SeaMonkey before 2.4 allow remote attackers to cause a denial of
  service (memory corruption and application crash) or possibly execute
  arbitrary code via unknown vectors (CVE-2011-2995).

  Unspecified vulnerability in the plugin API in Mozilla Firefox 3.6.x
  before 3.6.23 allows remote attackers to cause a denial of service
  (memory corruption and application crash) or possibly execute arbitrary
  code via unknown vectors (CVE-2011-2996).

  Mozilla Firefox before 3.6.23 and 4.x through 5, Thunderbird before
  6.0, and SeaMonkey before 2.3 do not properly handle location as the
  name of a frame, which allows remote attackers to bypass the Same
  Origin Policy via a crafted web site, a different vulnerability than
  CVE-2010-0170 (CVE-2011-2999).

  Mozilla Firefox before 3.6.23 and 4.x through 6, Thunderbird before
  7.0, and SeaMonkey before 2.4 do not properly handle HTTP responses
  that contain multiple Location, Content-Length, or Content-Disposition
  headers, which makes it easier for remote attackers to conduct HTTP
  response splitting attacks via crafted header values (CVE-2011-3000).

  Mozilla Firefox 4.x through 6, Thunderbird before 7.0, and SeaMonkey
  before 2.4 do not prevent manual add-on installation in response
  to the holding of the Enter key, which allows user-assisted remote
  attackers to bypass intended access restrictions via a crafted web
  site that triggers an unspecified internal error (CVE-2011-3001).

  Integer underflow in Mozilla Firefox 3.6.x before 3.6.23 allows
  remote attackers to cause a denial of service (application crash)
  or possibly execute arbitrary code via JavaScript code containing a
  large RegExp expression (CVE-2011-3867).

  Packages for 2009.0 are provided as of the Extended Maintenance
  Program. Additionally, some packages which require so, have been rebuilt and
  are being provided as updates.");
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

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird", rpm:"mozilla-thunderbird~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-af", rpm:"mozilla-thunderbird-af~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ar", rpm:"mozilla-thunderbird-ar~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-be", rpm:"mozilla-thunderbird-be~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-beagle", rpm:"mozilla-thunderbird-beagle~0.3.9~40.20mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-bg", rpm:"mozilla-thunderbird-bg~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-bn_BD", rpm:"mozilla-thunderbird-bn_BD~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ca", rpm:"mozilla-thunderbird-ca~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-cs", rpm:"mozilla-thunderbird-cs~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-da", rpm:"mozilla-thunderbird-da~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-de", rpm:"mozilla-thunderbird-de~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-el", rpm:"mozilla-thunderbird-el~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-en_GB", rpm:"mozilla-thunderbird-en_GB~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail", rpm:"mozilla-thunderbird-enigmail~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ar", rpm:"mozilla-thunderbird-enigmail-ar~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ca", rpm:"mozilla-thunderbird-enigmail-ca~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-cs", rpm:"mozilla-thunderbird-enigmail-cs~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-de", rpm:"mozilla-thunderbird-enigmail-de~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-el", rpm:"mozilla-thunderbird-enigmail-el~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-es", rpm:"mozilla-thunderbird-enigmail-es~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fi", rpm:"mozilla-thunderbird-enigmail-fi~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fr", rpm:"mozilla-thunderbird-enigmail-fr~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-hu", rpm:"mozilla-thunderbird-enigmail-hu~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-it", rpm:"mozilla-thunderbird-enigmail-it~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ja", rpm:"mozilla-thunderbird-enigmail-ja~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ko", rpm:"mozilla-thunderbird-enigmail-ko~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nb", rpm:"mozilla-thunderbird-enigmail-nb~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nl", rpm:"mozilla-thunderbird-enigmail-nl~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pl", rpm:"mozilla-thunderbird-enigmail-pl~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt", rpm:"mozilla-thunderbird-enigmail-pt~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt_BR", rpm:"mozilla-thunderbird-enigmail-pt_BR~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ru", rpm:"mozilla-thunderbird-enigmail-ru~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sl", rpm:"mozilla-thunderbird-enigmail-sl~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sv", rpm:"mozilla-thunderbird-enigmail-sv~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-tr", rpm:"mozilla-thunderbird-enigmail-tr~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-vi", rpm:"mozilla-thunderbird-enigmail-vi~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_CN", rpm:"mozilla-thunderbird-enigmail-zh_CN~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_TW", rpm:"mozilla-thunderbird-enigmail-zh_TW~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-es_AR", rpm:"mozilla-thunderbird-es_AR~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-es_ES", rpm:"mozilla-thunderbird-es_ES~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-et", rpm:"mozilla-thunderbird-et~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-et_EE", rpm:"mozilla-thunderbird-et_EE~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-eu", rpm:"mozilla-thunderbird-eu~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fi", rpm:"mozilla-thunderbird-fi~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fr", rpm:"mozilla-thunderbird-fr~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fy", rpm:"mozilla-thunderbird-fy~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ga", rpm:"mozilla-thunderbird-ga~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-gd", rpm:"mozilla-thunderbird-gd~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-gl", rpm:"mozilla-thunderbird-gl~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-he", rpm:"mozilla-thunderbird-he~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-hu", rpm:"mozilla-thunderbird-hu~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-id", rpm:"mozilla-thunderbird-id~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-is", rpm:"mozilla-thunderbird-is~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-it", rpm:"mozilla-thunderbird-it~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ja", rpm:"mozilla-thunderbird-ja~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ka", rpm:"mozilla-thunderbird-ka~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ko", rpm:"mozilla-thunderbird-ko~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-lightning", rpm:"mozilla-thunderbird-lightning~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-lt", rpm:"mozilla-thunderbird-lt~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nb_NO", rpm:"mozilla-thunderbird-nb_NO~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nl", rpm:"mozilla-thunderbird-nl~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nn_NO", rpm:"mozilla-thunderbird-nn_NO~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pa_IN", rpm:"mozilla-thunderbird-pa_IN~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pl", rpm:"mozilla-thunderbird-pl~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pt_BR", rpm:"mozilla-thunderbird-pt_BR~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pt_PT", rpm:"mozilla-thunderbird-pt_PT~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ro", rpm:"mozilla-thunderbird-ro~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ru", rpm:"mozilla-thunderbird-ru~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-si", rpm:"mozilla-thunderbird-si~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sk", rpm:"mozilla-thunderbird-sk~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sl", rpm:"mozilla-thunderbird-sl~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sq", rpm:"mozilla-thunderbird-sq~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sr", rpm:"mozilla-thunderbird-sr~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sv_SE", rpm:"mozilla-thunderbird-sv_SE~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-tr", rpm:"mozilla-thunderbird-tr~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-uk", rpm:"mozilla-thunderbird-uk~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-vi", rpm:"mozilla-thunderbird-vi~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-zh_CN", rpm:"mozilla-thunderbird-zh_CN~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-zh_TW", rpm:"mozilla-thunderbird-zh_TW~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nsinstall", rpm:"nsinstall~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-l10n", rpm:"mozilla-thunderbird-l10n~3.1.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird", rpm:"mozilla-thunderbird~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-af", rpm:"mozilla-thunderbird-af~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ar", rpm:"mozilla-thunderbird-ar~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-be", rpm:"mozilla-thunderbird-be~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-beagle", rpm:"mozilla-thunderbird-beagle~0.3.8~13.42mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-bg", rpm:"mozilla-thunderbird-bg~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-bn_BD", rpm:"mozilla-thunderbird-bn_BD~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ca", rpm:"mozilla-thunderbird-ca~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-cs", rpm:"mozilla-thunderbird-cs~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-da", rpm:"mozilla-thunderbird-da~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-de", rpm:"mozilla-thunderbird-de~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-el", rpm:"mozilla-thunderbird-el~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-en_GB", rpm:"mozilla-thunderbird-en_GB~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail", rpm:"mozilla-thunderbird-enigmail~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ar", rpm:"mozilla-thunderbird-enigmail-ar~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ca", rpm:"mozilla-thunderbird-enigmail-ca~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-cs", rpm:"mozilla-thunderbird-enigmail-cs~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-de", rpm:"mozilla-thunderbird-enigmail-de~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-el", rpm:"mozilla-thunderbird-enigmail-el~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-es", rpm:"mozilla-thunderbird-enigmail-es~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fi", rpm:"mozilla-thunderbird-enigmail-fi~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fr", rpm:"mozilla-thunderbird-enigmail-fr~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-hu", rpm:"mozilla-thunderbird-enigmail-hu~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-it", rpm:"mozilla-thunderbird-enigmail-it~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ja", rpm:"mozilla-thunderbird-enigmail-ja~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ko", rpm:"mozilla-thunderbird-enigmail-ko~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nb", rpm:"mozilla-thunderbird-enigmail-nb~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nl", rpm:"mozilla-thunderbird-enigmail-nl~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pl", rpm:"mozilla-thunderbird-enigmail-pl~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt", rpm:"mozilla-thunderbird-enigmail-pt~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt_BR", rpm:"mozilla-thunderbird-enigmail-pt_BR~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ru", rpm:"mozilla-thunderbird-enigmail-ru~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sl", rpm:"mozilla-thunderbird-enigmail-sl~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sv", rpm:"mozilla-thunderbird-enigmail-sv~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-tr", rpm:"mozilla-thunderbird-enigmail-tr~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-vi", rpm:"mozilla-thunderbird-enigmail-vi~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_CN", rpm:"mozilla-thunderbird-enigmail-zh_CN~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_TW", rpm:"mozilla-thunderbird-enigmail-zh_TW~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-es_AR", rpm:"mozilla-thunderbird-es_AR~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-es_ES", rpm:"mozilla-thunderbird-es_ES~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-et", rpm:"mozilla-thunderbird-et~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-et_EE", rpm:"mozilla-thunderbird-et_EE~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-eu", rpm:"mozilla-thunderbird-eu~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fi", rpm:"mozilla-thunderbird-fi~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fr", rpm:"mozilla-thunderbird-fr~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-fy", rpm:"mozilla-thunderbird-fy~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ga", rpm:"mozilla-thunderbird-ga~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-gd", rpm:"mozilla-thunderbird-gd~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-gl", rpm:"mozilla-thunderbird-gl~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-he", rpm:"mozilla-thunderbird-he~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-hu", rpm:"mozilla-thunderbird-hu~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-id", rpm:"mozilla-thunderbird-id~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-is", rpm:"mozilla-thunderbird-is~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-it", rpm:"mozilla-thunderbird-it~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ja", rpm:"mozilla-thunderbird-ja~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ka", rpm:"mozilla-thunderbird-ka~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ko", rpm:"mozilla-thunderbird-ko~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-lightning", rpm:"mozilla-thunderbird-lightning~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-lt", rpm:"mozilla-thunderbird-lt~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nb_NO", rpm:"mozilla-thunderbird-nb_NO~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nl", rpm:"mozilla-thunderbird-nl~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-nn_NO", rpm:"mozilla-thunderbird-nn_NO~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pa_IN", rpm:"mozilla-thunderbird-pa_IN~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pl", rpm:"mozilla-thunderbird-pl~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pt_BR", rpm:"mozilla-thunderbird-pt_BR~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-pt_PT", rpm:"mozilla-thunderbird-pt_PT~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ro", rpm:"mozilla-thunderbird-ro~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-ru", rpm:"mozilla-thunderbird-ru~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-si", rpm:"mozilla-thunderbird-si~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sk", rpm:"mozilla-thunderbird-sk~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sl", rpm:"mozilla-thunderbird-sl~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sq", rpm:"mozilla-thunderbird-sq~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sr", rpm:"mozilla-thunderbird-sr~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-sv_SE", rpm:"mozilla-thunderbird-sv_SE~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-tr", rpm:"mozilla-thunderbird-tr~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-uk", rpm:"mozilla-thunderbird-uk~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-vi", rpm:"mozilla-thunderbird-vi~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-zh_CN", rpm:"mozilla-thunderbird-zh_CN~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-zh_TW", rpm:"mozilla-thunderbird-zh_TW~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nsinstall", rpm:"nsinstall~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-l10n", rpm:"mozilla-thunderbird-l10n~3.1.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

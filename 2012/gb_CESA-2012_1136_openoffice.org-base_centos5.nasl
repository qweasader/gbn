# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-August/018780.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881465");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-08-03 11:17:16 +0530 (Fri, 03 Aug 2012)");
  script_cve_id("CVE-2012-2665");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2012:1136");
  script_name("CentOS Update for openoffice.org-base CESA-2012:1136 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openoffice.org-base'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"openoffice.org-base on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"OpenOffice.org is an office productivity suite that includes desktop
  applications, such as a word processor, spreadsheet application,
  presentation manager, formula editor, and a drawing program.

  Multiple heap-based buffer overflow flaws were found in the way
  OpenOffice.org processed encryption information in the manifest files of
  OpenDocument Format files. An attacker could provide a specially-crafted
  OpenDocument Format file that, when opened in an OpenOffice.org
  application, would cause the application to crash or, potentially, execute
  arbitrary code with the privileges of the user running the application.
  (CVE-2012-2665)

  Upstream acknowledges Timo Warns as the original reporter of these issues.

  All OpenOffice.org users are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues. All running
  instances of OpenOffice.org applications must be restarted for this update
  to take effect.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"openoffice.org-base", rpm:"openoffice.org-base~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-calc", rpm:"openoffice.org-calc~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-core", rpm:"openoffice.org-core~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-draw", rpm:"openoffice.org-draw~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-emailmerge", rpm:"openoffice.org-emailmerge~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-graphicfilter", rpm:"openoffice.org-graphicfilter~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-headless", rpm:"openoffice.org-headless~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-impress", rpm:"openoffice.org-impress~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-javafilter", rpm:"openoffice.org-javafilter~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-af_ZA", rpm:"openoffice.org-langpack-af_ZA~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ar", rpm:"openoffice.org-langpack-ar~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-as_IN", rpm:"openoffice.org-langpack-as_IN~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-bg_BG", rpm:"openoffice.org-langpack-bg_BG~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-bn", rpm:"openoffice.org-langpack-bn~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ca_ES", rpm:"openoffice.org-langpack-ca_ES~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-cs_CZ", rpm:"openoffice.org-langpack-cs_CZ~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-cy_GB", rpm:"openoffice.org-langpack-cy_GB~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-da_DK", rpm:"openoffice.org-langpack-da_DK~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-de", rpm:"openoffice.org-langpack-de~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-el_GR", rpm:"openoffice.org-langpack-el_GR~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-es", rpm:"openoffice.org-langpack-es~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-et_EE", rpm:"openoffice.org-langpack-et_EE~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-eu_ES", rpm:"openoffice.org-langpack-eu_ES~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-fi_FI", rpm:"openoffice.org-langpack-fi_FI~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-fr", rpm:"openoffice.org-langpack-fr~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ga_IE", rpm:"openoffice.org-langpack-ga_IE~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-gl_ES", rpm:"openoffice.org-langpack-gl_ES~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-gu_IN", rpm:"openoffice.org-langpack-gu_IN~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-he_IL", rpm:"openoffice.org-langpack-he_IL~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-hi_IN", rpm:"openoffice.org-langpack-hi_IN~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-hr_HR", rpm:"openoffice.org-langpack-hr_HR~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-hu_HU", rpm:"openoffice.org-langpack-hu_HU~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-it", rpm:"openoffice.org-langpack-it~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ja_JP", rpm:"openoffice.org-langpack-ja_JP~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-kn_IN", rpm:"openoffice.org-langpack-kn_IN~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ko_KR", rpm:"openoffice.org-langpack-ko_KR~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-lt_LT", rpm:"openoffice.org-langpack-lt_LT~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ml_IN", rpm:"openoffice.org-langpack-ml_IN~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-mr_IN", rpm:"openoffice.org-langpack-mr_IN~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ms_MY", rpm:"openoffice.org-langpack-ms_MY~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-nb_NO", rpm:"openoffice.org-langpack-nb_NO~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-nl", rpm:"openoffice.org-langpack-nl~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-nn_NO", rpm:"openoffice.org-langpack-nn_NO~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-nr_ZA", rpm:"openoffice.org-langpack-nr_ZA~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-nso_ZA", rpm:"openoffice.org-langpack-nso_ZA~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-or_IN", rpm:"openoffice.org-langpack-or_IN~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-pa_IN", rpm:"openoffice.org-langpack-pa_IN~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-pl_PL", rpm:"openoffice.org-langpack-pl_PL~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-pt_BR", rpm:"openoffice.org-langpack-pt_BR~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-pt_PT", rpm:"openoffice.org-langpack-pt_PT~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ru", rpm:"openoffice.org-langpack-ru~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-sk_SK", rpm:"openoffice.org-langpack-sk_SK~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-sl_SI", rpm:"openoffice.org-langpack-sl_SI~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-sr_CS", rpm:"openoffice.org-langpack-sr_CS~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ss_ZA", rpm:"openoffice.org-langpack-ss_ZA~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-st_ZA", rpm:"openoffice.org-langpack-st_ZA~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-sv", rpm:"openoffice.org-langpack-sv~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ta_IN", rpm:"openoffice.org-langpack-ta_IN~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-te_IN", rpm:"openoffice.org-langpack-te_IN~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-th_TH", rpm:"openoffice.org-langpack-th_TH~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-tn_ZA", rpm:"openoffice.org-langpack-tn_ZA~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-tr_TR", rpm:"openoffice.org-langpack-tr_TR~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ts_ZA", rpm:"openoffice.org-langpack-ts_ZA~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ur", rpm:"openoffice.org-langpack-ur~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ve_ZA", rpm:"openoffice.org-langpack-ve_ZA~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-xh_ZA", rpm:"openoffice.org-langpack-xh_ZA~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-zh_CN", rpm:"openoffice.org-langpack-zh_CN~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-zh_TW", rpm:"openoffice.org-langpack-zh_TW~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-zu_ZA", rpm:"openoffice.org-langpack-zu_ZA~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-math", rpm:"openoffice.org-math~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-pyuno", rpm:"openoffice.org-pyuno~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-sdk", rpm:"openoffice.org-sdk~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-sdk-doc", rpm:"openoffice.org-sdk-doc~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-testtools", rpm:"openoffice.org-testtools~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-ure", rpm:"openoffice.org-ure~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-writer", rpm:"openoffice.org-writer~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-xsltfilter", rpm:"openoffice.org-xsltfilter~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org", rpm:"openoffice.org~3.1.1~19.10.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

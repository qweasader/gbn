# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/fedora-package-announce/2007-September/msg00097.html");
  script_oid("1.3.6.1.4.1.25623.1.0.861522");
  script_version("2023-07-06T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-06 05:05:36 +0000 (Thu, 06 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-27 16:01:32 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_xref(name:"FEDORA", value:"2007-2020");
  script_cve_id("CVE-2007-4650");
  script_name("Fedora Update for gallery2 FEDORA-2007-2020");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'gallery2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC7");
  script_tag(name:"affected", value:"gallery2 on Fedora 7");
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

if(release == "FC7")
{

  if ((res = isrpmvuln(pkg:"gallery2", rpm:"gallery2~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-webdav", rpm:"gallery2-webdav~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-imageframe", rpm:"gallery2-imageframe~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-mp3audio", rpm:"gallery2-mp3audio~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-sitemap", rpm:"gallery2-sitemap~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-publishxp", rpm:"gallery2-publishxp~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-hybrid", rpm:"gallery2-hybrid~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-search", rpm:"gallery2-search~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-dynamicalbum", rpm:"gallery2-dynamicalbum~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-exif", rpm:"gallery2-exif~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-digibug", rpm:"gallery2-digibug~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-albumselect", rpm:"gallery2-albumselect~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-panorama", rpm:"gallery2-panorama~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-rearrange", rpm:"gallery2-rearrange~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-slider", rpm:"gallery2-slider~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-thumbnail", rpm:"gallery2-thumbnail~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-imageblock", rpm:"gallery2-imageblock~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-slideshow", rpm:"gallery2-slideshow~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-floatrix", rpm:"gallery2-floatrix~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-thumbpage", rpm:"gallery2-thumbpage~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-uploadapplet", rpm:"gallery2-uploadapplet~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-keyalbum", rpm:"gallery2-keyalbum~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-classic", rpm:"gallery2-classic~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-rewrite", rpm:"gallery2-rewrite~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-linkitem", rpm:"gallery2-linkitem~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-ffmpeg", rpm:"gallery2-ffmpeg~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-quotas", rpm:"gallery2-quotas~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-rss", rpm:"gallery2-rss~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-cart", rpm:"gallery2-cart~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-netpbm", rpm:"gallery2-netpbm~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-photoaccess", rpm:"gallery2-photoaccess~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-zipcart", rpm:"gallery2-zipcart~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-fotokasten", rpm:"gallery2-fotokasten~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-rating", rpm:"gallery2-rating~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-dcraw", rpm:"gallery2-dcraw~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-flashvideo", rpm:"gallery2-flashvideo~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-carbon", rpm:"gallery2-carbon~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-watermark", rpm:"gallery2-watermark~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-matrix", rpm:"gallery2-matrix~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-icons", rpm:"gallery2-icons~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-webcam", rpm:"gallery2-webcam~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-hidden", rpm:"gallery2-hidden~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-useralbum", rpm:"gallery2-useralbum~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-slideshowapplet", rpm:"gallery2-slideshowapplet~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-nokiaupload", rpm:"gallery2-nokiaupload~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-debug", rpm:"gallery2-debug~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-getid3", rpm:"gallery2-getid3~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-colorpack", rpm:"gallery2-colorpack~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-tile", rpm:"gallery2-tile~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-mime", rpm:"gallery2-mime~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-register", rpm:"gallery2-register~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-sizelimit", rpm:"gallery2-sizelimit~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-permalinks", rpm:"gallery2-permalinks~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-members", rpm:"gallery2-members~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-captcha", rpm:"gallery2-captcha~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-replica", rpm:"gallery2-replica~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-newitems", rpm:"gallery2-newitems~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-ecard", rpm:"gallery2-ecard~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-ajaxian", rpm:"gallery2-ajaxian~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-imagemagick", rpm:"gallery2-imagemagick~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-gd", rpm:"gallery2-gd~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-picasa", rpm:"gallery2-picasa~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-squarethumb", rpm:"gallery2-squarethumb~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-remote", rpm:"gallery2-remote~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-comment", rpm:"gallery2-comment~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-shutterfly", rpm:"gallery2-shutterfly~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-httpauth", rpm:"gallery2-httpauth~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-customfield", rpm:"gallery2-customfield~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2", rpm:"gallery2~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-archiveupload", rpm:"gallery2-archiveupload~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-multiroot", rpm:"gallery2-multiroot~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-migrate", rpm:"gallery2-migrate~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-multilang", rpm:"gallery2-multilang~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-password", rpm:"gallery2-password~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-randomhighlight", rpm:"gallery2-randomhighlight~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-reupload", rpm:"gallery2-reupload~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-itemadd", rpm:"gallery2-itemadd~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gallery2-siriux", rpm:"gallery2-siriux~2.2~0.7.svn20070831.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
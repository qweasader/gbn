# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113634");
  script_version("2023-06-02T09:09:16+0000");
  script_tag(name:"last_modification", value:"2023-06-02 09:09:16 +0000 (Fri, 02 Jun 2023)");
  script_tag(name:"creation_date", value:"2020-01-27 10:34:33 +0100 (Mon, 27 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WordPress Plugin Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"summary", value:"Checks and reports which WordPress plugins are installed on the
  target system.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/");

  script_timeout(900);

  exit(0);
}

CPE = "cpe:/a:wordpress:wordpress";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "cpe.inc" );

if( ! port = get_app_port( cpe: CPE, service: "www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe: CPE, port: port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

# nb:
# - The format is: "[README_URL]", "[NAME]#---#[DETECTION PATTERN]#---#[VERSION REGEX]#---#[CPE]#---#[CHANGELOG REGEX (optional)]"
# - To make sure that we're not using two or more entries for the same file in this array (When e.g.
#   having two entries the foreach(keys()) loop would iterate over both items but the infos variable
#   in both iterations would only include the info from one of both entries two times) we can use
#   something like e.g. the following:
#   egrep -o '^"[^"]+",' gb_wordpress_plugin_http_detect.nasl | sort | uniq -d
#
plugins = make_array(
"404-to-301/readme.txt", "404 to 301 - Redirect, Log and Notify 404 Errors#---#=== 404 to 301 - Redirect, Log and Notify 404 Errors#---#Stable tag: ([0-9.]+)#---#cpe:/a:404_to_301_project:404_to_301",
"accelerated-mobile-pages/readme.txt", "AMP for WP#---#Accelerated Mobile Pages ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:ampforwp:accelerated_mobile_pages",
"accordions/readme.txt", "Accordion#---#=== Accordion#---#Stable tag: ([0-9.]+)#---#cpe:/a:pickplugins:accordion",
"acf-to-rest-api/readme.txt", "ACF to REST API#---#=== ACF to REST API ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:acf_to_rest_api_project:acf_to_rest_api",
"ad-inserter/readme.txt", "Ad Inserter#---#=== Ad Inserter#---#Stable tag: ([0-9.]+)#---#cpe:/a:ad_inserter_project:ad_inserter",
"adamrob-parallax-scroll/readme.txt", "Parallax Scroll#---#Parallax Scroll#---#Stable tag: ([0-9.]+)#---#cpe:/a:parallax_scroll_project:parallax_scroll",
"adaptive-images/readme.txt", "Adaptive Images#---#=== Adaptive Images for WordPress ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:nevma:adaptive_images",
"addons-for-elementor/readme.txt", "Livemesh Addons for Elementor#---#=== Livemesh Addons for Elementor#---#Stable tag: ([0-9.]+)#---#cpe:/a:livemeshelementor:addons_for_elementor",
"add-link-to-facebook/readme.txt", "add-link-to-facebook#---#Add Link to Facebook#---#Stable tag: ([0-9.]+)#---#cpe:/a:add_link_to_facebook_project:add_link_to_facebook",
"add-to-any/README.txt", "AddToAny Share Buttons#---#=== AddToAny Share Buttons#---#Stable tag: ([0-9.]+)#---#cpe:/a:addtoany:addtoany_share_buttons",
"advanced-access-manager/readme.txt", "Advanced Access Manager#---#=== Advanced Access Manager ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:advanced_access_manager_project:advanced_access_manager",
"advanced-cf7-db/README.txt", "Advanced Contact form 7 DB#---#=== Advanced Contact form 7 DB ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:vsourz:advanced_cf7_db",
"advanced-custom-fields/readme.txt", "Advanced Custom Fields#---#=== Advanced Custom Fields#---#= ([0-9.]+) =#---#cpe:/a:advancedcustomfields:advanced_custom_fields",
"advanced-custom-fields-pro/readme.txt", "Advanced Custom Fields Pro#---#=== Advanced Custom Fields Pro#---#= ([0-9.]+) =#---#cpe:/a:advancedcustomfields:advanced_custom_fields_pro",
"advanced-nocaptcha-recaptcha/readme.txt", "CAPTCHA 4WP#---#(CAPTCHA 4WP|Advanced noCaptcha)#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpwhitesecurity:captcha_4wp",
"advanced-tinymce-configuration/readme.txt", "Advanced TinyMCE Configuration#---#=== Advanced TinyMCE Configuration#---#Stable tag: ([0-9.]+)#---#cpe:/a:andrew_ozz:advanced_tinymce_configuration",
"advanced-woo-search/readme.txt", "Advanced Woo Search#---#=== Advanced Woo Search ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:advanced-woo-search:advanced_woo_search",
"affiliates-manager/readme.txt", "Affiliates Manager#---#=== Affiliates Manager#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpaffiliatemanager:affiliates_manager",
"ag-custom-admin/readme.txt", "Absolutely Glamorous Custom Admin#---#=== (Absolutely Glamorous|AG) Custom Admin#---#Stable tag: ([0-9.]+)#---#cpe:/a:cusmin:ag-custom-admin",
# nb: Starting with (probably) version 4.0.0, it seems the company and product name changed, thus NVD uses also the new CPE
# In the WP plugin page - Developers section, oldest tag found is 4.0.18
"ajax-search-for-woocommerce/readme.txt", "FiboSearch - Ajax Search for WooCommerce#---#Ajax Search for WooCommerce#---#Stable tag: ([0-9.]+)#---#cpe:/a:fibosearch:fibosearch",
"all-404-redirect-to-homepage/readme.txt", "All 404 Redirect to Homepage#---#=== All 404 Redirect to Homepage#---#Stable tag: ([0-9.]+)#---#cpe:/a:clogica:all_404_redirect_to_homepage",
"all-in-one-seo-pack/readme.txt", "All in One SEO#---#=== All in One SEO#---#Stable tag: ([0-9.]+)#---#cpe:/a:aioseo:all_in_one_seo",
"all-in-one-wp-migration/readme.txt", "All-in-One WP Migration#---#=== All-in-One WP Migration#---#Stable tag: ([0-9.]+)#---#cpe:/a:servmask:one-stop_wp_migration",
"all-in-one-wp-security-and-firewall/readme.txt", "All In One WP Security & Firewall#---#=== All In One WP Security & Firewall#---#= ([0-9.]+) =#---#cpe:/a:tipsandtricks-hq:all_in_one_wp_security_%26_firewall",
"anti-spam/readme.txt", "Titan Anti-spam & Security#---#=== Titan Anti-spam#---#== Changelog ==[^0-9]+([0-9.]+)#---#cpe:/a:cm-wp:titan_anti-spam_%26_security#---#([0-9.]+)",
"astra-sites/readme.txt", "Starter Templates - Elementor, Gutenberg & Beaver Builder Templates#---#=== Starter Templates#---#Stable tag: ([0-9.]+)#---#cpe:/a:brainstormforce:starter_templates",
"autoptimize/readme.txt", "Autoptimize#---#=== Autoptimize ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:autoptimize:autoptimize",
"backupwordpress/readme.txt", "BackUpWordPress#---#=== BackUpWordPress#---#== Changelog(.*)#---#cpe:/a:xibodevelopment:backupwordpress#---#[#]{3,4} ([0-9.][-.0-9a-zA-Z]+)",
"backwpup/readme.txt", "BackWPup#---#(BackWPup|WordPress Backup Plugin)#---#Stable tag: ([0-9.]+)#---#cpe:/a:inpsyde:backwpup",
"banner-management-for-woocommerce/readme.txt", "Category Banner Management for Woocommerce#---#=== Woocommerce Category Banner Management ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:multidots:woocommerce_category_banner_management",
"bbpress/readme.txt", "bbPress#---#=== bbPress ===#---#Stable tag: ([0-9.][-.0-9a-zA-Z]+)#---#cpe:/a:bbpress:bbpress",
"better-wp-security/readme.txt", "iThemes Security#---#=== (iThemes Security|Better WP Security)#---#Stable tag: ([0-9.]+)#---#cpe:/a:ithemes:ithemes_security",
"bft-autoresponder/readme.txt", "Arigato Autoresponder and Newsletter#---#(=== Arigato Autoresponder and Newsletter ===|Plugin Name: Arigato Autoresponder and Newsletter)#---#Stable tag: ([0-9.]+)#---#cpe:/a:kibokolabs:arigato_autoresponder_and_newsletter",
"blog2social/readme.txt", "Blog2Social#---#Blog2Social#---#Stable tag: ([0-9.]+)#---#cpe:/a:adenion:blog2social",
"bold-page-builder/readme.txt", "Bold Page Builder#---#=== Bold Page Builder#---#= ([0-9.]+) =#---#cpe:/a:bold-themes:bold_page_builder",
"booking/readme.txt", "Booking Calendar#---#=== Booking Calendar ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:booking_calendar_project:booking_calendar",
# nb: The readme.txt header was unchanged since version 16.0, but it contain a special character thus avoided using the full header for detection.
# Previous versions use 2 different headers which both start with same string, '=== Bookly '
"bookly-responsive-appointment-booking-tool/readme.txt", "Bookly#---#(=== Bookly |Bookly ===)#---#Stable tag: ([0-9.]+)#---#cpe:/a:booking-wp-plugin:bookly",
"breeze/readme.txt", "Breeze#---#=== Breeze - WordPress Cache Plugin#---#Stable tag: ([0-9.]+)#---#cpe:/a:cloudways:breeze",
"broken-link-checker/readme.txt", "Broken Link Checker#---#=== Broken Link Checker#---#Stable tag: ([0-9.]+)#---#cpe:/a:managewp:broken_link_checker",
"buddypress/readme.txt", "BuddyPress#---#BuddyPress#---#Stable tag: ([0-9.]+)#---#cpe:/a:buddypress:buddypress",
"calculated-fields-form/README.txt", "Calculated Fields Form#---#=== Calculated Fields Form#---#= ([0-9.]+) =#---#cpe:/a:codepeople:calculated_fields_form",
"calendar/readme.txt", "Calendar#---#=== Calendar ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:kieranoshea:calendar",
"capability-manager-enhanced/readme.txt", "PublishPress Capabilities#---#=== PublishPress Capabilities#---#Stable tag: ([0-9.]+)#---#cpe:/a:publishpress:capabilities",
"captcha/readme.txt", "captcha#---#Captcha by BestWebSoft#---#Stable tag: ([0-9.]+)#---#cpe:/a:simplywordpress:captcha",
"cartflows/readme.txt", "Funnel Builder by CartFlows#---#===( Funnel Builder by)? CartFlows#---#Stable tag: ([0-9.]+)#---#cpe:/a:cartflows:funnel_builder",
"chaty/readme.txt", "Premio Chaty#---#=== Floating Chat Widget: Contact Icons, Messages, Telegram, Email, SMS, Call Button#---#Stable tag: ([0-9.]+)#---#cpe:/a:premio:chaty",
"check-email/readme.txt", "Check & Log Email#---#=== Check (\& Log )?Email ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpchill:check_%26_log_email",
"checkout-plugins-stripe-woo/readme.txt", "Stripe Payments For WooCommerce by Checkout Plugins#---#=== (Checkout Plugins - Stripe for WooCommerce|Stripe Payments For WooCommerce by Checkout Plugins)#---#Stable tag: ([0-9.]+)#---#cpe:/a:checkoutplugins:stripe_payments_for_woocommerce",
"classic-editor/readme.txt", "Classic Editor#---#=== Classic Editor#---#Stable tag: ([0-9.]+)#---#cpe:/a:wordpressdotorg:classic_editor",
"cleantalk-spam-protect/readme.txt", "Spam protection, AntiSpam, FireWall by CleanTalk#---#CleanTalk#---#= ([0-9.]+) [^=]*=#---#cpe:/a:cleantalk:cleantalk-spam-protect",
"click-to-chat-for-whatsapp/readme.txt", "Click to Chat#---#=== Click to Chat#---#== Changelog(.*)#---#cpe:/a:holithemes:click_to_chat#---#= ([0-9.]+)",
"cmp-comming-soon-maintenance/readme.txt", "CMP - Coming Soon & Maintenance Plugin#---#=== CMP - Coming Soon & Maintenance Plugin by NiteoThemes#---#Stable tag: ([0-9.]+)#---#cpe:/a:niteothemes:cmp",
"cms-tree-page-view/readme.txt", "CMS Tree Page View#---#=== CMS Tree Page View#---#Stable tag: ([0-9.]+)#---#cpe:/a:jon_christopher:cms_tree_page_view",
"codepress-admin-columns/readme.txt", "Admin Columns#---#Admin Columns ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:admincolumns:admin_columns",
"code-snippets/readme.txt", "Code Snippets#---#=== Code Snippets ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:codesnippets:code_snippets",
"colorlib-login-customizer/readme.txt", "Custom Login Page Customizer by Colorlib#---#=== Custom Login Page Customizer by Colorlib#---#Stable tag: ([0-9.]+)#---#cpe:/a:colorlib:custom_login_page_customizer",
"community-events/readme.txt", "Community Events#---#Community Events#---#Stable tag: ([0-9.]+)#---#cpe:/a:community_events_project:community_events",
"companion-auto-update/readme.txt", "Companion Auto Update#---#=== (Companion Auto Update|Companion Revision Manager)#---#Stable tag: ([0-9.]+)#---#cpe:/a:codeermeneer:companion_auto_update",
"complianz-gdpr/readme.txt", "Complianz - GDPR/CCPA Cookie Consent#---#=== Complianz - GDPR/CCPA Cookie Consent#---#Stable tag: ([0-9.]+)#---#cpe:/a:really-simple-plugins:complianz",
"complianz-gdpr-premium/readme.txt", "Complianz - GDPR/CCPA Cookie Consent Premium#---#=== Complianz Privacy Suite \(GDPR/CCPA\) premium#---#Stable tag: ([0-9.]+)#---#cpe:/a:really-simple-plugins:complianz_premium",
"contact-form-7/readme.txt", "Contact Form 7#---#=== Contact Form 7 ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:rocklobster:contact_form_7",
"contact-form-7-simple-recaptcha/readme.txt", "Contact Form 7 Captcha#---#=== Contact Form 7 Captcha#---#Stable tag: ([0-9.]+)#---#cpe:/a:contact_form_7_captcha_project:contact_form_7_captcha",
"contact-form-7-datepicker/readme.txt", "Contact Form 7 Datepicker#---#(Datepicker for Contact Form 7|Easily add a date field using jQuery UI's datepicker to your CF7 forms)#---#Stable tag: ([0-9.]+)#---#cpe:/a:contact-form-7-datepicker_project:contact-form-7-datepicker",
"contact-form-cfdb7/readme.txt", "Contact Form 7 Database Addon - CFDB7#---#=== Contact Form 7 Database Addon - CFDB7#---#Stable tag: ([0-9.]+)#---#cpe:/a:ciphercoin:contact_form_7_database_addon",
"contact-form-builder/readme.txt", "WDContactFormBuilder#---#=== Contact Form Builder#---#Stable tag: ([0-9.]+)#---#cpe:/a:web-dorado:wp_form_builder",
"contact-form-maker/readme.txt", "Contact Form by WD#---#=== Contact Form#---#Stable tag: ([0-9.]+)#---#cpe:/a:web-dorado:contact_form",
"contact-form-to-email/readme.txt", "Contact Form Email#---#=== Contact Form Email ===#---#= ([0-9.]+) =#---#cpe:/a:codepeople:contact_form_email",
"cookie-law-info/readme.txt", "GDPR Cookie Consent#---#Cookie Law#---#Stable tag: ([0-9.]+)#---#cpe:/a:cookielawinfo:gdpr_cookie_consent",
"cookie-notice/readme.txt", "Cookie Notice & Compliance for GDPR / CCPA#---#=== Cookie Notice#---#Stable tag: ([0-9.]+)#---#cpe:/a:hu-manity:cookie_notice_%26_compliance_for_gdpr_%2f_ccpa",
"count-per-day/readme.txt", "count-per-day#---#=== Count per Day ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:count_per_day_project:count_per_day",
"creative-mail-by-constant-contact/readme.txt", "Creative Mail - Easier WordPress & WooCommerce Email Marketing#---#=== Creative Mail#---#Stable tag: ([0-9.]+)#---#cpe:/a:constantcontact:creative_mail",
"crelly-slider/readme.txt", "Crelly Slider#---#=== Crelly Slider#---#Stable tag: ([0-9.]+)#---#cpe:/a:crelly_slider_project:crelly_slider",
"cta/readme.txt", "WordPress Calls to Action#---#WordPress Calls to Action#---#Stable tag: ([0-9.]+)#---#cpe:/a:inboundnow:call_to_action",
"custom-facebook-feed/README.txt", "Smash Balloon Social Post Feed#---#=== Smash Balloon Social Post Feed#---#Stable tag: ([0-9.]+)#---#cpe:/a:smashballoon:smash_balloon_social_post_feed",
"custom-field-suite/readme.txt", "Custom Field Suite#---#=== Custom Field Suite ===#---#= ([0-9.]+)#---#cpe:/a:custom_field_suite_project:custom_field_suite",
"custom-sidebars/readme.txt", "Custom Sidebars#---#=== Custom Sidebars#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpmudev:custom_sidebars",
"data-tables-generator-by-supsystic/readme.txt", "Data Tables Generator by Supsystic#---#=== Data Tables Generator#---#Stable tag: ([0-9.]+)#---#cpe:/a:supsystic:data_tables_generator",
"disable-comments/readme.txt", "Disable Comments#---#Disable Comments#---#= ([0-9.]+) =#---#cpe:/a:disable_comments:disable_comments_project",
"download-manager/readme.txt", "Download Manager#---#Download Manager ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpdownloadmanager:wordpress_download_manager",
"download-monitor/readme.txt", "Download Monitor#---#=== Download Monitor ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpchill:download_monitor",
"drag-and-drop-multiple-file-upload-contact-form-7/readme.txt", "Drag and Drop Multiple File Upload - Contact Form 7#---#=== Drag and Drop Multiple File Upload#---#Stable tag: ([0-9.]+)#---#cpe:/a:codedropz:drag_and_drop_multiple_file_upload_-_contact_form_7",
"duplicate-page/readme.txt", "Duplicate Page#---#=== Duplicate Page#---#Stable tag: ([0-9.]+)#---#cpe:/a:duplicatepro:duplicate_page",
"duplicator/readme.txt", "Duplicator#---#Duplicator - WordPress Migration Plugin#---#Stable tag: ([0-9.]+)#---#cpe:/a:snapcreek:duplicator",
"easy-appointments/readme.txt", "Easy Appointments#---#=== Easy Appointments ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:easy_appointments_project:easy_appointments",
"easy-custom-auto-excerpt/readme.txt", "Easy Custom Auto Excerpt#---#=== Easy Custom Auto Excerpt ===#---#= ([0-9.]+) =#---#cpe:/a:tonjoostudio:easy_custom_auto_excerpt",
"easy-digital-downloads/readme.txt", "Easy Digital Downloads#---#=== Easy Digital Downloads#---#Stable tag: ([0-9.]+)#---#cpe:/a:sandhillsdev:easy_digital_downloads",
"easy-fancybox/readme.txt", "Easy FancyBox#---#=== Easy FancyBox#---#Stable tag: ([0-9.]+)#---#cpe:/a:status301:easy_fancybox",
"easy-testimonials/readme.txt", "Easy Testimonials#---#Easy Testimonials#---#Stable tag: ([0-9.]+)#---#cpe:/a:goldplugins:easy_testimonials",
"easy-wp-smtp/readme.txt", "Easy WP SMTP#---#Easy WP SMTP#---#Stable tag: ([0-9.]+)#---#cpe:/a:wp-ecommerce:easy_wp_smtp",
"elementskit-lite/readme.txt", "Elements kit Lite#---#=== Elements kit Elementor addons#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpmet:elements_kit_elementor_addons",
"elementor/readme.txt", "Elementor Website Builder#---#=== Elementor#---#Stable tag: ([0-9.]+)#---#cpe:/a:elementor:website_builder",
"email-subscribers/readme.txt", "Email Subscribers & Newsletters#---#=== Email Subscribers#---#Stable tag: ([0-9.]+)#---#cpe:/a:icegram:email_subscribers_%26_newsletters",
"envira-gallery-lite/readme.txt", "Envira Photo Gallery#---#Envira Gallery#---#== Changelog(.*)#---#cpe:/a:enviragallery:envira_gallery#---#=? ?([0-9.]+)",
"eps-301-redirects/readme.txt", "301 Redirects - Easy Redirect Manager#---#\*\*What is a 301 Redirect\?\*\*#---#Stable tag: ([0-9.]+)#---#cpe:/a:webfactoryltd:301_redirects",
"essential-addons-for-elementor-lite/readme.txt", "Essential Addons for Elementor#---#=== Essential Addons for Elementor#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpdeveloper:essential_addons_for_elementor",
"evalphp/readme.txt", "Eval PHP#---#This plugin runs native PHP code that can be added to post and page data\.#---#Stable tag: ([0-9.]+)#---#cpe:/a:flashpixx:evalphp",
"events-manager/readme.txt", "Events Manager#---#=== Events Manager ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:wp-events-plugin:events_manager",
"everest-forms/readme.txt", "Everest Forms#---#Everest Forms#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpeverest:everest_forms",
"export-all-urls/readme.txt", "Export All URLs#---#=== Export All URLs#---#Stable tag: ([0-9.]+)#---#cpe:/a:atlas_gondal:export_all_urls",
"export-users-to-csv/readme.txt", "export-users-to-csv#---#(Export users data and metadata to a csv file.|A WordPress plugin that exports user data and meta data.)#---#Stable tag: ([0-9.]+)#---#cpe:/a:export_users_to_csv_project:export_users_to_csv",
"facebook-by-weblizar/readme.txt", "Social LikeBox & Feed#---#=== (Facebook|Social LikeBox)#---#Stable tag: ([0-9.]+)#---#cpe:/a:weblizar:social_likebox_%26_feed",
"facebook-for-woocommerce/readme.txt", "Facebook for WooCommerce#---#=== Facebook for WooCommerce#---#= ([0-9.]+) (- [0-9-]+ )?=#---#cpe:/a:facebook:facebook_for_woocommerce",
"favicon-by-realfavicongenerator/README.txt", "Favicon by RealFaviconGenerator#---#=== Favicon by RealFaviconGenerator#---#Stable tag: ([0-9.]+)#---#cpe:/a:realfavicongenerator:favicon_by_realfavicongenerator",
"filebird/readme.txt", "FileBird - WordPress Media Library Folders & File Manager#---#=== FileBird#---#- Version ([0-9.]+)#---#cpe:/a:ninjateam:filebird",
"fluent-smtp/readme.txt", "FluentSMTP - WP Mail SMTP, Amazon SES, SendGrid, MailGun and Any SMTP Connector Plugin#---#=== FluentSMTP#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpmanageninja:fluentsmtp",
"font-awesome/readme.txt", "Font Awesome#---#=== Font Awesome ===#---#Stable tag: ([0-9.][-.0-9a-zA-Z]+)#---#cpe:/a:fontawesome:font_awesome",
"font-organizer/readme.txt", "font-organizer#---#=== Font Organizer ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:hivewebstudios:font_organizer",
"foogallery/README.txt", "FooGallery#---#=== FooGallery#---#== Changelog(.*)#---#cpe:/a:fooplugins:foogallery#---#= ([0-9.]+) =",
"form-maker/readme.txt", "FormMaker by 10Web#---#= Form Maker#---#Stable tag: ([0-9.]+)#---#cpe:/a:10web:form_maker",
"formidable/readme.txt", "Formidable Form Builder#---#(=== Formidable|Formidable Forms Builder for WordPress ===)#---#= ([0-9.]+) =#---#cpe:/a:strategy11:formidable_form_builder",
"forminator/readme.txt", "Forminator#---#=== Forminator#---#Stable tag: ([0-9.]+)#---#cpe:/a:incsub:forminator",
"fv-wordpress-flowplayer/readme.txt", "FV Flowplayer Video Player#---#=== (Flowplayer|FV) (Wordpress|Flowplayer)#---#== Changelog(.*)#---#cpe:/a:foliovision:fv_flowplayer_video_player#---#= ([0-9.]+)",
"gallery-bank/readme.txt", "Gallery Bank#---#Gallery Bank#---#Stable tag: ([0-9.]+)#---#cpe:/a:tech-banker:gallery_bank",
"gd-rating-system/readme.txt", "GD Rating System#---#GD Rating System#---#Version: ([0-9.]+)#---#cpe:/a:gd_rating_system_project:gd_rating_system",
"give/readme.txt", "GiveWP#---#=== Give#---#Stable tag: ([0-9.]+)#---#cpe:/a:givewp:givewp",
"googleanalytics/readme.txt", "(ShareThis Dashboard for |=== )Google Analytics#---#=== ShareThis Dashboard for Google Analytics#---#Stable tag: ([0-9.]+)#---#cpe:/a:sharethis:dashboard_for_google_analytics",
"google-analytics-dashboard-for-wp/readme.txt", "ExactMetrics - Google Analytics Dashboard for WordPress#---#=== (ExactMetrics|Google Analytics Dashboard)#---#Stable tag: ([0-9.]+)#---#cpe:/a:exactmetrics:exactmetrics",
"google-analyticator/readme.txt", "Google Analyticator#---#Google Analyticator#---#Stable tag: ([0-9.]+)#---#cpe:/a:sumo:google_analyticator",
"google-document-embedder/readme.txt", "Google Doc Embedder#---#=== Google Doc Embedder#---#= ([0-9.]+) =#---#cpe:/a:google_doc_embedder_project:google_doc_embedder",
"google-language-translator/readme.txt", "Translate WordPress - Google Language Translator#---#=== Translate WordPress - Google Language Translator#---#Stable tag: ([0-9.]+)#---#cpe:/a:gtranslate:google_language_translator",
"gotmls/readme.txt", "Anti-Malware Security and Brute-Force Firewall#---#=== Anti-Malware Security and Brute-Force Firewall#---#Stable tag: ([0-9.]+)#---#cpe:/a:anti-malware_security_and_brute-force_firewall_project:anti-malware_security_and_brute-force_firewall",
"gtranslate/readme.txt", "GTranslate#---#=== (GTranslate|Translate Wordpress with GTranslate)#---#Stable tag: ([0-9.]+)#---#cpe:/a:gtranslate:translate_wordpress_with_gtranslate",
"gwolle-gb/readme.txt", "Gwolle Guestbook#---#Gwolle Guestbook#---#Stable tag: ([0-9.]+)#---#cpe:/a:gwolle_guestbook_project:gwolle_guestbook",
"happy-elementor-addons/readme.txt", "Happy Addons for Elementor#---#=== Happy Addons for Elementor#---#Version: ([0-9.]+)#---#cpe:/a:wedevs:happy_addons_for_elementor",
"header-footer-code-manager/readme.txt", "Header Footer Code Manager#---#=== Header Footer Code Manager#---#Stable tag: ([0-9.]+)#---#cpe:/a:draftpress:header_footer_code_manager",
"header-footer-elementor/readme.txt", "Elementor - Header, Footer & Blocks Template#---#=== Elementor - Header, Footer & Blocks Template#---#Stable tag: ([0-9.]+)#---#cpe:/a:brainstormforce:elementor_-_header%2c_footer_%26_blocks_template",
"health-check/readme.txt", "Health Check & Troubleshooting#---#=== Health Check (===|& Troubleshooting ===)#---#Stable tag: ([0-9.]+)#---#cpe:/a:wordpress:health_check_%26_troubleshooting",
"hrm/readme.txt", "WP Human Resource Management#---#=== WP Human Resource Management ===#---#= ([0-9.]+) -#---#cpe:/a:mishubd:wp_human_resource_management",
"icegram/readme.txt", "Icegram#---#(=== Icegram|Icegram ===)#---#Stable tag: ([0-9.]+)#---#cpe:/a:icegram:icegram",
"iframe/readme.txt", "iframe#---#=== iframe ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:iframe_project:iframe",
"igniteup/readme.txt", "IgniteUp#---#=== IgniteUp#---#Stable tag: ([0-9.]+)#---#cpe:/a:getigniteup:igniteup",
"import-users-from-csv-with-meta/readme.txt", "Import users from CSV with meta#---#=== Import users from CSV with meta#---#Stable tag: ([0-9.]+)#---#cpe:/a:codection:import_users_from_csv_with_meta",
"insert-headers-and-footers/readme.txt", "WPCode - Insert Headers and Footers#---#Insert Headers and Footers#---#== Changelog(.*)#---#cpe:/a:wpcode:wpcode#---#= ([0-9.]+)",
"insert-php/readme.txt", "Woody ad snippets#---#=== (Insert PHP|PHP code snippets|Woody ad snippets)#---#= ([0-9.]+) =#---#cpe:/a:webcraftic:woody_ad_snippets",
"insta-gallery/readme.txt", "Social Feed Gallery#---#(Instagram Gallery|=== WP Social Feed Gallery)#---#Stable tag: ([0-9.]+)#---#cpe:/a:quadlayers:wp_social_feed_gallery",
"jetpack/readme.txt", "Jetpack - WP Security, Backup, Speed, & Growth#---#=== Jetpack (by WordPress.com|-WP Security, Backup, Speed, & Growth) ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:automattic:jetpack",
"kadence-starter-templates/readme.txt", "Starter Templates by Kadence WP#---#=== Starter Templates by Kadence WP #---#Stable tag: ([0-9.]+)#---#cpe:/a:kadencewp:starter_templates",
"kingcomposer/readme.txt", "KingComposer#---#KingComposer#---#= ([0-9.]+) \(#---#cpe:/a:king-theme:kingcomposer",
# === Google Analytics By Lara ===
# === Google Analytics ===
# === Lara's Google Analytics ===
"lara-google-analytics/readme.txt", "Lara's Google Analytics#---#===( Lara's)? Google Analytics (By Lara )?===#---#Stable tag: ([0-9.]+)#---#cpe:/a:lara%27s_google_analytics_project:lara%27s_google_analytics",
"launcher/readme.txt", "Launcher#---#=== Launcher#---#Stable tag: ([0-9.]+)#---#cpe:/a:mythemeshop:launcher",
"leadin/readme.txt", "HubSpot#---#=== HubSpot -#---#Stable tag: ([0-9.]+)#---#cpe:/a:hubspot:hubspot",
"learnpress/readme.txt", "LearnPress#---#=== LearnPress#---#Stable tag: ([0-9.]+)#---#cpe:/a:thimpress:learnpress",
"lifterlms/readme.txt", "LifterLMS#---#=== LifterLMS#---#Stable stag: ([0-9.]+)#---#cpe:/a:lifterlms:lifterlms",
"limit-login-attempts-reloaded/readme.txt", "Limit Login Attempts Reloaded#---#=== Limit Login Attempts Reloaded ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:limitloginattempts:limit_login_attempts_reloaded",
"litespeed-cache/readme.txt", "LiteSpeed Cache#---#=== LiteSpeed Cache ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:litespeedtech:litespeed_cache",
"loco-translate/readme.txt", "Loco Translate#---#=== Loco Translate#---#Stable tag: ([0-9.]+)#---#cpe:/a:loco_translate_project:loco_translate",
"login-or-logout-menu-item/readme.txt", "Login or Logout Menu Item#---#=== Login or Logout Menu Item#---#Stable tag: ([0-9.]+)#---#cpe:/a:login_or_logout_menu_item_project:login_or_logout_menu_item",
"loginizer/readme.txt", "Loginizer#---#Loginizer#---#Stable tag: ([0-9.]+)#---#cpe:/a:loginizer:loginizer",
"loginpress/readme.txt", "LoginPress#---#(=== LoginPress|LoginPress ===)#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpbrigade:loginpress",
# nb: Up until version 1.0.8, inside README.txt there is no Changelog and Stable tag: is only correct in most recent versions.
# There is a changelog.md file, up to version 2.1.0, valid from the first available version.
# Sadly, there is no distinct identify element inside changelog.md, thus detection based on it was ignored for now.
"mailchimp-for-woocommerce/README.txt", "Mailchimp for WooCommerce#---#=== Mailchimp for WooCommerce ===#---#= ([0-9.]+) =#---#cpe:/a:mailchimp:mailchimp_for_woocommerce",
"mailchimp-for-wp/readme.txt", "MC4WP: Mailchimp for WordPress#---#Mail[cC]himp for WordPress#---#Stable tag: ([0-9.]+)#---#cpe:/a:mailchimp_for_wordpress_project:mailchimp_for_wordpress",
"mainwp-child/readme.txt", "MainWP Child#---#=== MainWP Child -#---#Stable tag: ([0-9.]+)#---#cpe:/a:mainwp:mainwp_child",
"maintenance/readme.txt", "Maintenance#---#=== Maintenance#---#Stable tag: ([0-9.]+)#---#cpe:/a:webfactoryltd:maintenance",
"mappress-google-maps-for-wordpress/readme.txt", "MapPress Maps for WordPress#---#=== MapPress#---#Stable tag: ([0-9.]+)#---#cpe:/a:mappresspro:mappress",
"master-slider/README.txt", "Master Slider#---#=== Master Slider#---#Stable tag: ([0-9.]+)#---#cpe:/a:averta:master_slider",
"media-file-manager/readme.txt", "media-file-manager#---#Media File Manager#---#Stable tag: ([0-9.]+)#---#cpe:/a:media_file_manager_project:media_file_manager",
"media-from-ftp/readme.txt", "Media from FTP#---#=== Media From FTP ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:media_from_ftp_project:media_from_ftp",
"media-library-assistant/readme.txt", "Media Library Assistant#---#Media Library Assistant#---#Stable tag: ([0-9.]+)#---#cpe:/a:media_library_assistant_project:media_library_assistant",
"mesmerize-companion/readme.txt", "Mesmerize Companion#---#=== Mesmerize Companion#---#Stable tag: ([0-9.]+)#---#cpe:/a:mesmerize_companion_project:mesmerize_companion",
"meta-box/readme.txt", "Meta Box#---#=== Meta Box#---#Stable tag: ([0-9.]+)#---#cpe:/a:metabox:meta_box",
"metform/readme.txt", "Metform Elementor Contact Form Builder#---#=== Metform Elementor#---#Stable tag: ([0-9.][-.0-9a-zA-Z]+)#---#cpe:/a:wpmet:metform_elementor_contact_form_builder",
"miniorange-saml-20-single-sign-on/readme.txt", "SAML SP Single Sign On - SSO login#---#(miniOrange|Single Sign On)#---#Stable tag: ([0-9.]+)#---#cpe:/a:miniorange:saml_sp_single_sign_on",
"modern-events-calendar-lite/readme.txt", "Modern Events Calendar Lite#---#=== Modern Events Calendar Lite ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:webnus:modern_events_calendar_lite",
# nb: Up to version 2.3.6 the version file is README.txt thus it had to be separated with readme.txt so we could gather all versions
"modula-best-grid-gallery/README.txt", "Modula Image Gallery#---# Modula #---#Stable tag: ([0-9.]+)#---#cpe:/a:wpchill:customizable_wordpress_gallery_plugin_-_modula_image_gallery",
"modula-best-grid-gallery/readme.txt", "Modula Image Gallery#---# Modula Image Gallery ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpchill:customizable_wordpress_gallery_plugin_-_modula_image_gallery",
"multi-step-form/readme.txt", "Multi Step Form#---#=== Multi Step Form#---#= ([0-9.]+) =#---#cpe:/a:mondula:multi_step_form",
"my-calendar/readme.txt", "My Calendar#---#=== My Calendar#---#= ([0-9.]+) =#---#cpe:/a:my_calendar_project:my_calendar",
"newsletter/readme.txt", "Newsletter#---#=== Newsletter ===#---#== Changelog ==(.+)#---#cpe:/a:thenewsletterplugin:newsletter#---#==? ([0-9.]+) ==?",
"newstatpress/readme.txt", "NewStatPress#---#(NewStatPress|StatPress)#---#Stable tag: ([0-9.]+)#---#cpe:/a:newstatpress_project:newstatpress",
"nextgen-gallery/readme.txt", "NextGEN Gallery#---#NextGEN Gallery#---#Stable tag: ([0-9.]+)#---#cpe:/a:imagely:nextgen_gallery",
"ninja-forms/readme.txt", "Ninja Forms#---#=== Ninja Forms#---#Stable tag: ([0-9.]+)#---#cpe:/a:ninjaforms:contact_form",
"ocean-extra/readme.txt", "Ocean Extra#---#=== Ocean Extra#---#Stable tag: ([0-9.]+)#---#cpe:/a:oceanwp:ocean_extra",
"official-facebook-pixel/readme.txt", "Facebook for Wordpress#---#=== (Facebook for WordPress|Official Facebook Pixel) ===#---#== Changelog(.*)#---#cpe:/a:facebook:official-facebook-pixel#---# version ([0-9.]+) =",
"official-statcounter-plugin-for-wordpress/readme.txt", "StatCounter - Free Real Time Visitor Stats#---#=== StatCounter - Free Real Time Visitor Stats#---#Stable tag: ([0-9.]+)#---#cpe:/a:statcounter:statcounter",
"olympus-google-fonts/readme.txt", "Google Fonts Typography#---#=== Fonts Plugin | Google Fonts Typography#---#Stable tag: ([0-9.]+)#---#cpe:/a:fontsplugin:fonts",
"one-click-demo-import/readme.txt", "One Click Demo Import#---#=== One Click Demo Import ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:ocdi:one_click_demo_import",
"one-click-ssl/readme.txt", "One Click SSL#---#=== One Click SSL#---#Stable tag: ([0-9.]+)#---#cpe:/a:tribulant:one_click_ssl",
"onesignal-free-web-push-notifications/readme.txt", "OneSignal - Web Push Notifications#---#=== OneSignal#---#Stable tag: ([0-9.]+)#---#cpe:/a:onesignal:onesignal-free-web-push-notifications",
"online-lesson-booking-system/readme.txt", "Online Lesson Booking#---#=== Online Lesson Booking ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:sukimalab:online_lesson_booking",
"optinmonster/readme.txt", "OptinMonster#---#=== WordPress Popups for Marketing and Email Newsletters, Lead Generation and Conversions by OptinMonster#---#Stable tag: ([0-9.]+)#---#cpe:/a:optinmonster:optinmonster",
"option-tree/readme.txt", "OptionTree#---#=== OptionTree#---#Stable tag: ([0-9.]+)#---#cpe:/a:optiontree_project:optiontree",
"paid-memberships-pro/readme.txt", "Paid Memberships Pro#---#Paid Memberships Pro#---#Stable tag: ([0-9.]+)#---#cpe:/a:strangerstudios:paid_memberships_pro",
"peters-login-redirect/readme.txt", "Peter's Login Redirect#---#(Peter's Login|Defining redirect rules per role)#---#= ([0-9.]+) =#---#cpe:/a:profilepress:loginwp",
"pdf-embedder/readme.txt", "PDF Embedder#---#(=== PDF Embedder|\[pdf-embedder url=)#---#Stable tag: ([0-9.]+)#---#cpe:/a:wp-pdf:pdf_embedder",
# nb: Up until version 3.0.1, inside README.txt there is an undisclosed name === Plugin Name ===.
"photo-gallery/readme.txt", "Photo Gallery by 10Web#---#(=== Gallery ===|Photo Gallery by 10Web|Photo Gallery by WD)#---#Stable tag: ([0-9.]+)#---#cpe:/a:10web:photo_gallery",
"pixelyoursite/readme.txt", "PixelYourSite#---#===PixelYourSite#---#Stable tag: ([0-9.]+)#---#cpe:/a:pixelyoursite:pixelyoursite",
"pods/readme.txt", "Pods#---#=== Pods#---#Stable tag: ([0-9.]+)#---#cpe:/a:podsfoundation:pods",
"popup-builder/readme.txt", "Popup Builder#---#Popup Builder#---#== Changelog(.*)#---#cpe:/a:sygnoos:popup_builder#---#Version ([0-9.]+)",
"post-duplicator/readme.txt", "Post Duplicator#---#=== Post Duplicator#---#Stable tag: ([0-9.]+)#---#cpe:/a:metaphorcreations:post_duplicator",
"post-expirator/readme.txt", "Post Expirator#---#=== Post Expirator:#---#Stable tag: ([0-9.]+)#---#cpe:/a:publishpress:post_expirator",
"popup-maker/readme.txt", "Popup Maker#---#=== Popup Maker#---#Stable tag: ([0-9.]+)#---#cpe:/a:code-atlantic:popup_maker",
"post-smtp/readme.txt", "Post SMTP Mailer/Email Log#---#=== Post SMTP Mailer/Email Log#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpexperts:post_smtp",
"post-views-counter/readme.txt", "Post Views Counter#---#=== Post Views Counter#---#Stable tag: ([0-9.]+)#---#cpe:/a:dfactory:post_views_counter",
"premium-addons-for-elementor/readme.txt", "Premium Addons for Elementor#---#=== Premium Addons for Elementor#---#Stable tag: ([0-9.]+)#---#cpe:/a:leap13:premium_addons_for_elementor",
"pricing-table-by-supsystic/readme.txt", "Pricing Table by Supsystic#---#Pricing Table by Supsystic#---#Stable tag: ([0-9.]+)#---#cpe:/a:supsystic:pricing_table_by_supsystic",
"print-my-blog/readme.txt", "Print My Blog#---#=== Print My Blog ===#---#= ([0-9.]+)#---#cpe:/a:print_my_blog_project:print_my_blog",
"profile-builder/readme.txt", "Profile Builder#---#Profile Builder#---#Stable tag: ([0-9.]+)#---#cpe:/a:cozmoslabs:profile_builder",
"ps-phpcaptcha/readme.txt", "PS PHPCaptcha WP#---#=== PS PHPCaptcha WP ===#---#= ([0-9.]+) =#---#cpe:/a:ps_phpcaptcha_wp_project:ps_phpcaptcha_wp",
"quiz-master-next/readme.txt", "Quiz And Survey Master#---#=== (Quiz Master Next|Quiz And Survey Master)#---#Stable tag: ([0-9.]+)#---#cpe:/a:expresstech:quiz_and_survey_master",
"real-cookie-banner/CHANGELOG.md", "Real Cookie Banner#---#wordpress.org/plugins/real-cookie-banner#---## ([0-9.]+)#---#cpe:/a:devowl:wordpress_real_cookie_banner",
"real-time-find-and-replace/readme.txt", "Real-Time Find and Replace#---#=== Real-Time Find and Replace#---#== Changelog(.*)#---#cpe:/a:infolific:real-time_find_and_replace#---#= ([0-9.]+) =",
"redux-framework/readme.txt", "Gutenberg Template Library & Redux Framework#---#=== Gutenberg Template Library & Redux Framework#---#Stable tag: ([0-9.]+)#---#cpe:/a:redux:gutenberg_template_library_%26_redux_framework",
"relevanssi/readme.txt", "Relevanssi#---#Relevanssi - A Better Search#---#Stable tag: ([0-9.]+)#---#cpe:/a:relevanssi:relevanssi",
"remove-footer-credit/readme.txt", "Remove Footer Credit#---#=== Remove Footer Credit ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpchill:remove_footer_credit",
"responsive-add-ons/readme.txt", "Gutenberg & Elementor Templates Importer For Responsive#---#(Gutenberg & Elementor Templates Importer For Responsive|Responsive Ready Sites Importer|Adds Google, Yahoo and Bing verification codes and adds Site Statistics scripts to your site)#---#Stable tag: ([0-9.]+)#---#cpe:/a:cyberchimps:gutenberg_%26_elementor_templates_importer_for_responsive",
"responsive-menu/readme.txt", "Responsive Menu#---#=== Responsive Menu#---#Stable tag: ([0-9.]+)#---#cpe:/a:expresstech:responsive_menu",
"responsive-vector-maps/readme.txt", "RVM - Responsive Vector Maps#---#=== RVM - Responsive Vector Maps#---#Stable tag: ([0-9.]+)#---#cpe:/a:thinkupthemes:responsive_vector_maps",
"restaurant-reservations/readme.txt", "Five Star Restaurant Reservations#---#=== (Five Star )?Restaurant Reservations #---#Stable tag: ([0-9.]+)#---#cpe:/a:fivestarplugins:five_star_restaurant_reservations",
"restaurant-reservations/readme.md", "Five Star Restaurant Reservations#---## Restaurant Reservations#---#Stable tag: ([0-9.]+)#---#cpe:/a:fivestarplugins:five_star_restaurant_reservations",
"role-scoper/readme.txt", "Role Scoper#---#Role Scoper#---#Stable tag: ([0-9.]+)#---#cpe:/a:role_scoper_project:role_scoper",
"royal-elementor-addons/readme.txt", "Royal Elementor Addons and Templates#---#=== Royal Elementor Addons #---#Stable tag: ([0-9.]+)#---#cpe:/a:royal-elementor-addons:royal_elementor_addons",
"safe-svg/readme.txt", "Safe SVG#---#=== Safe SVG ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:safe_svg_project:safe_svg",
"sagepay-server-gateway-for-woocommerce/readme.txt", "SagePay Server Gateway for WooCommerce#---#=== SagePay Server Gateway for WooCommerce ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:patsatech:sagepay_server_gateway_for_woocommerce",
"sassy-social-share/readme.txt", "Sassy Social Share#---#=== Social Sharing Plugin - Sassy Social Share#---#Stable tag: ([0-9.]+)#---#cpe:/a:heateor:sassy_social_share",
"seo-by-rank-math/readme.txt", "WordPress SEO Plugin - Rank Math#---#=== (WordPress SEO Plugin - Rank Math|Rank Math SEO)#---#Stable tag: ([0-9.]+)#---#cpe:/a:rankmath:seo",
"shapepress-dsgvo/README.txt", "WP DSGVO Tools#---#=== WP DSGVO Tools#---#Stable tag: ([0-9.]+)#---#cpe:/a:shapepress:wp_dsgvo_tools",
"shortcodes-ultimate/readme.txt", "Shortcodes Ultimate#---## WordPress Shortcodes Plugin#---#Stable tag: ([0-9.]+)#---#cpe:/a:getshortcodes:shortcodes_ultimate",
"simple-301-redirects-addon-bulk-uploader/readme.txt", "Simple 301 Redirects - Addon - Bulk Uploader#---#=== Simple 301 Redirects#---#= ([0-9.]+) =#---#cpe:/a:webcraftic:simple_301_redirects-addon-bulk_uploader",
"simple-301-redirects/readme.txt", "Simple 301 Redirects by BetterLinks#---#=== Simple 301 Redirects#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpdeveloper:simple_301_redirects",
"simple-download-monitor/readme.txt", "Simple Download Monitor#---#Simple Download Monitor#---#Stable tag: ([0-9.]+)#---#cpe:/a:simple_download_monitor_project:simple_download_monitor",
"simple-fields/readme.txt", "simple-fields#---#=== Simple Fields#---#Stable tag: ([0-9.]+)#---#cpe:/a:simple_fields_project:simple_fields",
"simple-membership/readme.txt", "Simple Membership#---#=== Simple Membership#---#Stable tag: ([0-9.]+)#---#cpe:/a:simple-membership-plugin:simple_membership",
"simple-social-buttons/readme.txt", "Simple Social Media Share Buttons#---#=== Simple Social Media Share Buttons#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpbrigade:simple_social_buttons",
"siteorigin-panels/readme.txt", "Page Builder by SiteOrigin#---#=== Page Builder by SiteOrigin ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:siteorigin:page_builder",
"slideshow-gallery/readme.txt", "Slideshow Gallery#---#=== Slideshow Gallery ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:tribulant:slideshow_gallery",
"smart-google-code-inserter/readme.txt", "Smart Google Code Inserter#---#Stable tag: ([0-9.]+)#---#cpe:/a:oturia:smart_google_code_inserter",
"smart-slider-3/readme.txt", "Smart Slider 3#---#=== Smart Slider 3 ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:nextendweb:smart_slider_3",
"social-networks-auto-poster-facebook-twitter-g/readme.txt", "NextScripts: Social Networks Auto-Poster#---#=== NextScripts: Social Networks Auto-Poster ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:nextscripts:social_networks_auto_poster",
"social-pug/readme.txt", "Social Sharing Buttons - Grow#---#(Social Sharing Buttongs|Grow|Social Pug)#---#Stable tag: ([0-9.]+)#---#cpe:/a:devpups:social_pug",
"social-rocket/readme.txt", "Social Rocket#---#=== Social Rocket#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpsocialrocket:social_sharing",
"social-warfare/readme.txt", "Social Warfare#---#Social Warfare ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:warfareplugins:social_warfare",
"spam-byebye/readme.txt", "spam-byebye#---#SPAM-BYEBYE#---#Stable tag: ([0-9.]+)#---#cpe:/a:ohtan:spam-byebye",
"squirrly-seo/readme.txt", "SEO Plugin by Squirrly SEO#---#=== (SEO (Plugin |[0-9]+ )*by squirrly|Squirrly SEO)#---#== Changelog(.*)#---#cpe:/a:squirrly:seo#---#= ([0-9.]+)",
"stops-core-theme-and-plugin-updates/readme.txt", "Easy Updates Manager#---#=== (Easy Updates Manager|Disable Updates Manager|Disable All Updates)#---#= ([0-9.]+) (- [0-9-]+ )?=#---#cpe:/a:easyupdatesmanager:easy_updates_manager",
"string-locator/readme.txt", "String locator#---#=== String locator ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:instawp:string_locator",
"strong-testimonials/readme.txt", "Strong Testimonials#---#=== Strong Testimonials ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:machothemes:strong_testimonials",
#
# On 1.1.2 - 1.1.6:
# === Sucuri Sitecheck Free Security Scanner ===
# On 1.3+:
# === Sucuri Security - SiteCheck Malware Scanner ===
# On at least 1.6.9+:
# === Sucuri Security - Auditing, Malware Scanner and Hardening ===
#
"sucuri-scanner/readme.txt", "Sucuri Security#---#=== Sucuri (Security|Sitecheck)#---#Stable tag:[ ]*([0-9.]+)#---#cpe:/a:sucuri:security",
"supportcandy/readme.txt", "SupportCandy#---#=== SupportCandy ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:supportcandy:supportcandy",
"svg-support/readme.txt", "SVG Support#---#=== SVG Support ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:benbodhi:svg_support",
"svg-vector-icon-plugin/readme.txt", "WP SVG Icons#---#=== (WP SVG Icons|WordPress Icons (SVG)|WordPress Icons - SVG)#---#Stable tag: ([0-9.]+)#---#cpe:/a:wp_svg_icons_project:wp_svg_icons",
"tablepress/readme.txt", "TablePress#---#=== TablePress#---#Stable tag: ([0-9.]+)#---#cpe:/a:tablepress:tablepress",
"table-of-contents-plus/readme.txt", "Table of Contents Plus#---#=== Table of Contents Plus ===#---#== Changelog(.*)#---#cpe:/a:table_of_contents_plus_project:table_of_contents_plus#---#= ([0-9.]+)",
"tabs-responsive/readme.txt", "Tabs#---#=== Tabs ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpshopmart:tabs_responsive",
"tatsu/changelog.md", "Tatsu#---#^v[0-9.]+#---#v([0-9.]+) #---#cpe:/a:brandexponents:tatsu",
"tc-custom-javascript/readme.txt", "TC Custom JavaScript#---#=== TC Custom JavaScript ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:tc_custom_javascript_project:tc_custom_javascript",
"the-events-calendar/readme.txt", "The Events Calendar#---#=== The Events Calendar#---#Stable tag: ([0-9.]+)#---#cpe:/a:tri:the_events_calendar",
"themegrill-demo-importer/readme.txt", "ThemeGrill Demo Importer#---#=== ThemeGrill Demo Importer ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:themegrill:themegrill_demo_importer",
"testimonial-rotator/readme.txt", "Testimonial Rotator#---#Easily add (Testimonials to your WordPress Blog|and manage Testimonials to your site\.)#---#== Changelog(.*)#---#cpe:/a:testimonial_rotator_project:testimonial_rotator#---#= ([0-9.]+) [-=]",
"ti-woocommerce-wishlist/readme.txt", "TI WooCommerce Wishlist#---#=== TI WooCommerce Wishlist#---#Stable tag: ([0-9.]+)#---#cpe:/a:templateinvaders:ti_woocommerce_wishlist",
"tinymce-advanced/readme.txt", "Advanced Editor Tools#---#=== Advanced Editor Tools \(previously TinyMCE Advanced\)#---#Stable tag: ([0-9.]+)#---#cpe:/a:automattic:advanced_editor_tools",
"translatepress-multilingual/readme.txt", "TranslatePress#---#=== Translate Multilingual sites - TranslatePress#---#Stable tag: ([0-9.]+)#---#cpe:/a:cozmoslabs:translatepress",
"two-factor/readme.txt", "Two-Factor#---#=== Two-Factor ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:plugin_contributors:two_factor",
"two-factor-authentication/readme.txt", "Two Factor Authentication#---#=== Two Factor Authentication ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:simbahosting:two-factor-authentication",
"uk-cookie-consent/readme.txt", "GDPR Cookie Consent Banner#---#=== Cookie Consent ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:catapultthemes:cookie_consent",
"ultimate-faqs/readme.txt", "Ultimate FAQ#---#(=== Ultimate FAQ|[ultimate-faqs])#---#= ([0-9.]+) =#---#cpe:/a:etoilewebdesign:ultimate_faq",
"ultimate-form-builder-lite/readme.txt", "Contact Form for WordPress - Ultimate Form Builder Lite#---#Ultimate Form Builder Lite ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:accesspressthemes:ultimate-form-builder-lite",
"ultimate-member/readme.txt", "Ultimate Member#---#=== Ultimate Member#---#Stable tag: ([0-9.]+)#---#cpe:/a:ultimatemember:ultimate_member",
"updraftplus/readme.txt", "UpdraftPlus#---#UpdraftPlus#---#Stable tag: ([0-9.]+)#---#cpe:/a:updraftplus:updraftplus",
"use-any-font/readme.txt", "Use Any Font - Custom Font Uploader#---#=== Use Any Font#---#Stable tag: ([0-9.]+)#---#cpe:/a:use_any_font_project:use_any_font",
"users-customers-import-export-for-wp-woocommerce/readme.txt", "Import Export WordPress Users#---#(WordPress Users & WooCommerce Customers Import Export|Import Export WordPress Users)#---#Stable tag: ([0-9.]+)#---#cpe:/a:webtoffee:import_export_wordpress_users",
"visitors-traffic-real-time-statistics/readme.txt", "Visitor Traffic Real Time Statistics#---#=== Visitors? Traffic Real Time Statistics#---#= ([0-9.]+) =#---#cpe:/a:wp-buy:visitor_traffic_real_time_statistics",
"visualizer/readme.txt", "Visualizer#---#=== (Visualizer|WordPress Charts and Graphs)#---#= ([0-9.]+) (- [0-9-]+ +)?=#---#cpe:/a:themeisle:visualizer",
"w3-total-cache/readme.txt", "W3 Total Cache#---#W3 Total Cache#---#Stable tag: ([0-9.]+)#---#cpe:/a:boldgrid:w3_total_cache",
# nb: Only version 4.1.0 started to document the changes in the readme.txt and that file has only:
# "Stable tag: trunk" for all releases (starting from 1.0.0 up to 4.1.1) so we need to use the
# changelog.txt here instead.
"webp-converter-for-media/changelog.txt", "WebP Converter for Media#---#== Changelog ==#---#= ([0-9.]+) #---#cpe:/a:webp_converter_for_media_project:webp_converter_for_media",
"webp-express/README.txt", "WebP Express#---#=== WebP Express#---#Stable tag: ([0-9.]+)#---#cpe:/a:bitwise-it:webp-express",
"web-stories/readme.txt", "Web Stories#---#=== Web Stories ===#---#== Changelog(.*)#---#cpe:/a:google:web_stories#---#= ([0-9.]+)",
"white-label-cms/readme.txt", "White Label CMS#---#=== White Label CMS#---#Stable tag: ([0-9.]+)#---#cpe:/a:videousermanuals:white_label_cms",
"widget-google-reviews/readme.txt", "Plugin for Google Reviews#---#=== (Google Reviews Widget|(Widget|Plugin) for Google Reviews) ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:richplugins:plugin_for_google_reviews",
"widget-logic/readme.txt", "Widget Logic#---#=== Widget Logic ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpchef:widget_logic",
"wise-chat/readme.txt", "Wise Chat#---#=== Wise Chat ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:kaine:wise_chat",
"wonderm00ns-simple-facebook-open-graph-tags/readme.txt", "Open Graph and Twitter Card Tags#---#=== Open Graph for Facebook, Google+ and Twitter Card Tags#---#Stable tag: ([0-9.]+)#---#cpe:/a:webdados:open_graph_for_facebook%2c_google%2b_and_twitter_card_tags",
"woo-gutenberg-products-block/readme.txt", "WooCommerce Blocks#---#=== WooCommerce (Gutenberg|Blocks)#---#Stable tag: ([0-9.]+)#---#cpe:/a:automattic:woocommerce_blocks",
"woo-order-export-lite/readme.txt", "Advanced Order Export For WooCommerce#---#=== Advanced Order Export For WooCommerce ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:algolplus:advanced_order_export",
"woo-variation-swatches/README.txt", "Variation Swatches for WooCommerce#---#=== Variation Swatches for WooCommerce= ([0-9.]+) - #---#cpe:/a:variation_swatches_for_woocommerce_project:variation_swatches_for_woocommerce",
"woocommerce-payments/readme.txt", "WooCommerce Payments#---#=== WooCommerce Payments#---#Stable tag: ([0-9.]+)#---#cpe:/a:automatic:woocommerce_payments",
"woocommerce-checkout-manager/readme.txt", "WooCommerce Checkout Manager#---#=== WooCommerce Checkout Manager ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:visser:woocommerce_checkout_manager",
"woocommerce-mercadopago/readme.txt", "Mercado Pago payments for WooCommerce#---#(=== WooCommerce MercadoPago ===|=== Mercado Pago payments for WooCommerce ===)#---#== Changelog(.*)#---#cpe:/a:mercadopago:mercado_pago_payments_for_woocommerce#---#= v?([0-9.][-.0-9a-zA-Z]+)",
# nb: The proper title in the WooCommerce PDF readme.txt was used only from version 1.6.6 onward,
# but the alternative text occurs in all version as part of specific URLs.
"woocommerce-pdf-invoices-packing-slips/readme.txt", "WooCommerce PDF Invoices & Packing Slips#---#(=== WooCommerce PDF Invoices & Packing Slips ===|https://wpovernight.com/downloads/woocommerce-pdf-invoices-packing-slips)#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpovernight:woocommerce_pdf_invoices%26_packing_slips",
"woocommerce-products-filter/readme.txt", "HUSKY - Products Filter for WooCommerce Professional#---#=== (WOOF|HUSKY|WooCommerce) (-\s)*Products Filter#---#Stable tag: ([0-9.]+)#---#cpe:/a:pluginus:woocommerce_products_filter",
"woocommerce-subscriptions/readme.txt", "WooCommerce Subscriptions#---#WooCommerce Subscriptions ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:woocommerce:subscriptions",
"woocommerce/readme.txt", "WooCommerce#---#WooCommerce#---#Stable tag: ([0-9.]+)#---#cpe:/a:woocommerce:woocommerce",
"woolentor-addons/readme.txt", "ShopLentor#---#=== (ShopLentor|WooLentor)#---#Changelog(.*)#---#cpe:/a:hasthemes:woolentor_-_woocommerce_elementor_addons_%2b_builder#---#= Version: ([0-9.]+)",
"wordfence/readme.txt", "Wordfence Security#---#=== Wordfence Security - Firewall & Malware Scan ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:wordfence:wordfence_security",
"wordpress-database-reset/readme.txt", "WP Database Reset#---#=== (WordPress Database Reset|WP Database Reset)#---#Stable tag: ([0-9.]+)#---#cpe:/a:webfactoryltd:wp_database_reset",
"wordpress-popular-posts/readme.txt", "WordPress Popular Posts#---#=== WordPress Popular Posts#---#Stable tag: ([0-9.]+)#---#cpe:/a:wordpress_popular_posts_project:wordpress_popular_posts",
"wordpress-seo/readme.txt", "Yoast SEO#---#=== Yoast SEO ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:yoast:yoast_seo",
"wptouch/readme.txt", "WPtouch#---#Tags: wptouch#---#Stable tag: ([0-9.]+)#---#cpe:/a:bravenewcode:wptouch",
"wpvivid-backuprestore/readme.txt", "Migration, Backup, Staging - WPvivid#---#=== Migration, Backup, Staging - WPvivid ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpvivid:migration%2c_backup%2c_staging",
"wp-all-import/readme.txt", "Import any XML or CSV File to WordPress#---#=== (WP All Import|Import any XML or CSV File to WordPress)#---#Stable tag: ([0-9.]+)#---#cpe:/a:soflyy:wp_all_import",
"wp-asset-clean-up/readme.txt", "Asset CleanUp: Page Speed Booster#---#=== Asset CleanUp: Page Speed Booster ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:asset_cleanup%3a_page_speed_booster_project:asset_cleanup%3a_page_speed_booster",
"wp-booking-system/readme.txt", "WP Booking System#---#=== WP Booking System ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpbookingsystem:wp_booking_system",
"wp-central/readme.txt", "wpCentral#---#=== wp[Cc]entral ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpcentral:wpcentral",
"wp-content-copy-protector/readme.txt", "WP Content Copy Protection & No Right Click#---#=== WP Content Copy Protection & No Right Click#---#Stable tag: ([0-9.]+)#---#cpe:/a:wp-buy:wp_content_copy_protection_%26_no_right_click",
"wp-database-backup/readme.txt", "WP Database Backup#---#=== WP Database Backup#---#= ([0-9.]+) =#---#cpe:/a:wpseeds:wp_database_backup",
"wp-db-backup/readme.txt", "Database Backup for WordPress#---#=== Database Backup for WordPress#---#Stable tag: ([0-9.]+)#---#cpe:/a:deliciousbrains:database_backup",
"wp-discourse/readme.txt", "WP Discourse#---#=== WP Discourse ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:discourse:wp_discourse",
"wp-editor/readme.txt", "WP Editor#---#=== WP Editor#---#Stable tag: ([0-9.]+)#---#cpe:/a:wp_editor_project:wp_editor",
"wp-fastest-cache/readme.txt", "WP Fastest Cache#---#=== WP Fastest Cache#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpfastestcache:wp_fastest_cache",
"wp-file-manager/readme.txt", "File Manager#---#=== File Manager ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:mndpsingh287:wp-file-manager",
"wp-gdpr-compliance/readme.txt", "WP GDRP Compliance#---#WP GDPR Compliance#---#Stable tag: ([0-9.]+)#---#cpe:/a:cookieinformation:wp-gdpr-compliance",
"wp-google-map-plugin/readme.txt", "WP Google Map Plugin#---#(WP Google Map Plugin|flippercode)#---#== Changelog(.*)#---#cpe:/a:flippercode:wp_google_map#---#= ([0-9.]+) =",
"wp-google-maps/readme.txt", "WP Google Maps#---#=== WP Google Maps ===#---#== Changelog(.*)#---#cpe:/a:codecabin:wp_go_maps#---#[=*] ([0-9.]+)",
"wp-inject/readme.txt", "ImageInject#---#ImageInject#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpscoop:imageinject",
"wp-live-chat-support/readme.txt", "WP-Live Chat by 3CX#---#=== WP Live Chat Support ===#---#== Changelog ==(.*)#---#cpe:/a:3cx:wp-live-chat-support#---#= ([0-9.]+)",
"wp-maintenance-mode/readme.txt", "WP Maintenance Mode#---#=== WP Maintenance Mode ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:designmodo:wp_maintenance_mode",
"wp-members/readme.txt", "WP-Members Membership Plugin#---#=== WP-Members Membership Plugin#---#Stable tag: ([0-9.]+)#---#cpe:/a:wp-members_project:wp-members",
"wp-meta-seo/readme.txt", "WP Meta SEO#---#=== WP Meta SEO ===#---#== Changelog ==(.*)#---#cpe:/a:joomunited:wp_meta_seo#---#= ([0-9.]+)",
"wp-noexternallinks/readme.txt", "wp-noexternallinks#---#WP No External Links#---#Stable tag: ([0-9.]+)#---#cpe:/a:wp_no_external_links_project:wp_no_external_links",
"wp-reset/readme.txt", "WP Reset - Most Advanced WordPress Reset Tool#---#=== WP Reset#---#Stable tag: ([0-9.]+)#---#cpe:/a:webfactoryltd:wp_reset",
"wp-retina-2x/readme.txt", "WP Retina 2x#---#=== WP Retina 2x#---#Stable tag: ([0-9.]+)#---#cpe:/a:meowapps:wp_retina_2x",
"wp-seopress/readme.txt", "SEOPress, on-site SEO#---#=== SEOPress, on-site SEO#---#Stable tag: ([0-9.]+)#---#cpe:/a:seopress:seopress",
"wp-sitemap-page/readme.txt", "WP Sitemap Page#---#=== WP Sitemap Page#---#Stable tag: ([0-9.]+)#---#cpe:/a:wp_sitemap_page_project:wp_sitemap_page",
"wp-slimstat/readme.txt", "Slimstat Analytics#---#=== (WP Slim[Ss]tat|Slimstat Analytics)#---#Stable tag: ([0-9.]+)#---#cpe:/a:wp-slimstat:slimstat_analytics",
"wp-smushit/readme.txt", "Smush#---#Smush Image Compression and Optimization#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpmudev:smush_image_compression_and_optimization",
"wp-statistics/readme.txt", "WP Statistics#---#=== WP Statistics#---#Stable tag: ([0-9.]+)#---#cpe:/a:veronalabs:wp_statistics",
"wp-super-cache/readme.txt", "WP Super Cache#---# WP Super Cache #---#Stable tag: ([0-9.]+)#---#cpe:/a:automattic:wp_super_cache",
"wp-support-plus-responsive-ticket-system/readme.txt", "WP Support Plus Responsive Ticket System#---#=== WP Support Plus Responsive Ticket System ===#---#= V ([0-9.]+) =#---#cpe:/a:wpsupportplus:wp_support_plus_responsive_ticket_system",
"wp-ultimate-csv-importer/Readme.txt", "Import and Export WordPress Data as CSV or XML#---#Ultimate CSV Importer#---#Stable tag: ([0-9.]+)#---#cpe:/a:smackcoders:wp-ultimate-csv-importer",
"wp-ultimate-recipe/readme.txt", "WP Ultimate Recipe#---#=== WP Ultimate Recipe#---#= ([0-9.]+) =#---#cpe:/a:bootstrapped:wp_ultimate_recipe",
#
# On 3.0 only:
# === User Profiles, User Registration, Login & Membership - ProfilePress  (Formerly WP User Avatar) ===
# On 3.1+:
# === User Registration, User Profiles, Login & Membership - ProfilePress (Formerly WP User Avatar) ===
# On at least 3.1.19+:
# === User Registration, Login Form, User Profile & Membership - ProfilePress (Formerly WP User Avatar) ===
#
# nb: The "-" is the "En Dash Unicode Character" (U+2013) but it was replaced in the examples above
# to avoid a reporting of the QA due to unsupported chars in a VT.
"wp-user-avatar/readme.txt", "ProfilePress#---#=== (User (Registration, Login Form, User Profile|Profiles, User Registration, Login|Registration, User Profiles, Login) & Membership|[^=]+ProfilePress\s+\(Formerly WP User Avatar\))#---#Stable tag: ([0-9.]+)#---#cpe:/a:profilepress:profilepress",
"wp-cerber/readme.txt", "WP Cerber Security, Anti-spam & Malware Scan#---#=== WP Cerber Security, Anti-spam & Malware Scan#---#Stable tag: ([0-9.]+)#---#cpe:/a:cerber:wp_cerber_security%2c_anti-spam_%26_malware_scan",
"wpcf7-redirect/readme.txt", "Redirection for Contact Form 7#---#=== Redirection for Contact Form 7#---#Stable tag: ([0-9.]+)#---#cpe:/a:querysol:redirection_for_contact_form_7",
"wpdiscuz/readme.txt", "wpDiscuz#---#wpDiscuz ===#---#Stable tag: ([0-9.]+)#---#cpe:/a:gvectors:wpdiscuz",
"wpforms-lite/readme.txt", "WPForms Contact Form#---#(WPForms Lite ===|=== Contact Form by WPForms)#---#= ([0-9.]+) =#---#cpe:/a:wpforms:contact_form",
"wpforo/readme.txt", "wpForo Forum#---#(wpForo|Forum)#---#Stable tag: ([0-9.]+)#---#cpe:/a:gvectors:wpforo_forum",
"wpfront-scroll-top/readme.txt", "WPFront Scroll Top#---#=== WPFront Scroll Top#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpfront:scroll_top",
"wps-hide-login/readme.txt", "WPS Hide Login#---#=== WPS Hide Login#---#Stable tag: ([0-9.]+)#---#cpe:/a:wpserveur:wps_hide_login",
"yet-another-related-posts-plugin/readme.txt", "YARPP - Yet Another Related Posts Plugin#---#Yet Another Related Posts Plugin#---#Stable tag: ([0-9.]+)#---#cpe:/a:yarpp:yet_another_related_posts_plugin",
"yellow-pencil-visual-theme-customizer/readme.txt", "Visual CSS Style Editor#---#=== Visual CSS Style Editor#---#= ([0-9.]+) =#---#cpe:/a:yellowpencil:visual_css_style_editor",
"yikes-inc-easy-mailchimp-extender/readme.txt", "Easy Forms for Mailchimp#---#=== (Easy Forms|Easy MailChimp Forms|YIKES)#---#Stable tag: ([0-9.]+)#---#cpe:/a:yikesinc:easy_forms_for_mailchimp",
"yop-poll/readme.txt", "YOP Poll#---#=== YOP Poll ===#---#= ([0-9.]+) =#---#cpe:/a:yop-poll:yop_poll",
"youtube-embed-plus/readme.txt", "Embed Plus for YouTube#---#YouTube#---#Stable tag: ([0-9.]+)#---#cpe:/a:embedplus:youtube"
);

foreach readme( keys( plugins ) ) {

  if( ! infos = plugins[readme] )
    continue;

  infos = split( infos, sep: "#---#", keep: FALSE );
  if( ! infos || max_index( infos ) < 4 )
    continue;

  name = infos[0];
  detect_regex = infos[1];
  vers_regex = infos[2];
  cpe = infos[3] + ":";
  changelog_regex = infos[4];

  if( ! changelog_regex )
    changelog_regex = "= ([0-9.]+) =";

  url = dir + "/wp-content/plugins/" + readme;
  res = http_get_cache( port: port, item: url );
  if( egrep( pattern: detect_regex, string: res, icase: TRUE ) && ( res =~ "Change( ){0,1}log" || res =~ "Tested up to: ([0-9.]+)" || res =~ "\* (Added|Fixed): " ) ) {
    if( "Changelog" >< vers_regex && cl = eregmatch( pattern: vers_regex, string: res, icase: TRUE ) ) {
      vers = eregmatch( pattern: changelog_regex, string: cl[1], icase: TRUE );
    } else {
      vers = eregmatch( pattern: vers_regex, string: res, icase: TRUE );
    }

    if( ! vers[1] )
      continue;

    version = vers[1];

    # nb: The Tatsu plugin is using "changelog.md" while the "WebP Converter for Media" changelog.txt
    kb_entry_name = ereg_replace( pattern: "/(readme|changelog)\.(md|txt)", string: readme, replace: "", icase: TRUE );
    insloc = ereg_replace( pattern: "/(readme|changelog)\.(md|txt)", string: url, replace: "", icase: TRUE );

    # nb: Usually only the one without the "/http/" should be used for version checks.
    set_kb_item( name: "wordpress/plugin/" + kb_entry_name + "/detected", value: TRUE );
    set_kb_item( name: "wordpress/plugin/http/" + kb_entry_name + "/detected", value: TRUE );
    # nb: Some generic KB keys if we ever need to run this if multiple themes have been detected.
    set_kb_item( name: "wordpress/plugin/detected", value: TRUE );
    set_kb_item( name: "wordpress/plugin/http/detected", value: TRUE );

    extra = "Plugin Page: https://wordpress.org/plugins/" + kb_entry_name + "/";

    register_and_report_cpe( app: name,
                             ver: version,
                             concluded: vers[0],
                             base: cpe,
                             expr: "([0-9.]+)",
                             insloc: insloc,
                             regPort: port,
                             regService: "www",
                             conclUrl: http_report_vuln_url( port: port, url: url, url_only: TRUE ),
                             extra: extra );
  }
}

exit( 0 );

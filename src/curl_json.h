// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PRCYCOIN_CURLJSON_H
#define PRCYCOIN_CURLJSON_H

#include <curl/curl.h>

#include <string>

#define TIME_IN_US 1
#define TIMETYPE curl_off_t
#define TIMEOPT CURLINFO_TOTAL_TIME_T
#define MINIMAL_PROGRESS_FUNCTIONALITY_INTERVAL     3000000

struct CurlProgress {
  TIMETYPE lastruntime; /* type depends on version, see above */
  CURL *curl;
};

struct JsonDownload {
    std::string URL = "";
    std::string response = "";
    bool failed = false;
    bool complete = false;
    CURL *curl;
    CurlProgress prog;
};

extern JsonDownload downloadedJSON;

static size_t writer(char *in, size_t size, size_t nmemb, std::string *out);
extern void getHttpsJson(std::string url);

#endif

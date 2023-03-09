// Copyright (c) 2018 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PRCYcoin_INVALID_OUTPOINTS_JSON_H
#define PRCYcoin_INVALID_OUTPOINTS_JSON_H
#include <string>

std::string LoadInvalidOutPoints()
{
    std::string str = "[\n"
            "  {\n"
            "    \"txid\": \"5280c9c4d94f48da118559505031cecc0c730052b0bb38b98d0950f503b1c17e\",\n"
            "    \"n\": 0\n"
            "  },\n"
            "  {\n"
            "    \"txid\": \"f018e1cb852403152fd5c80f5eaa4696da217e19f139215fcd58ca5430a53a9e\",\n"
            "    \"n\": 0\n"
            "  }\n"
            "]";
    return str;
}

#endif //PRCYcoin_INVALID_OUTPOINTS_JSON_H

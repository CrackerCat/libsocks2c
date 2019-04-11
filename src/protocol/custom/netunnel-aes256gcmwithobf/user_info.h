#pragma once

#include <glob.h>

class UserInfo
{
public:

    UserInfo(size_t id) {}

    void SetUid(size_t id) { uid = id;}

    size_t GetUid() {return uid;}

private:

    static size_t uid;
};
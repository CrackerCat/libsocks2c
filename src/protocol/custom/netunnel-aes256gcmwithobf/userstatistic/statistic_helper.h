#pragma once
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>

enum TrafficType {
    TCP,
    UDP,
    RAW
};

#ifdef BUILD_NETUNNEL_SERVER
#include <ozo/request.h>
#include <ozo/connection_info.h>
#include <ozo/shortcuts.h>
#include "../../../../utils/logger.h"

#include <ozo/query_builder.h>

#include "../../../../utils/sqlhost.h"

const std::chrono::milliseconds ConnectorTimeout(500);
const std::chrono::milliseconds WriteTimeout(500);

// dump statistic when session is closing
class StatisticHelper{

public:

    static char* TrafficTypeToStr(TrafficType type)
    {
        switch (type)
        {
            case TCP:
            {
                return "TCP";
            }
            case UDP:
            {
                return "UDP";
            }
        }

    }

    #define str(x) std::to_string(x)

    static void DumpTrafficIntoSql(boost::asio::io_context* io, uint32_t uid, size_t upstream_size, size_t downstream_size, std::string& src, std::string& dst, TrafficType type)
    {
        if (!io) return;
        if (upstream_size == 0 || downstream_size == 0) return;

        char sql_str[512];

        // dst might exceed the buff
        if (dst.size() >= 256) {
            dst = dst.substr(0, 256);
            LOG_INFO("cut str to {}", dst)
        }

        sprintf(sql_str, "INSERT INTO user_statistic (uid, src_host, dst_host, upstream_traffic, downstream_traffic, type) values(%d, '%s', '%s', %ld, %ld, '%s');", uid, src.c_str(), dst.c_str(), upstream_size, downstream_size, TrafficTypeToStr(type));

        //std::string sql_str(sql);

        auto record_query = ozo::make_query_builder(boost::hana::make_tuple(ozo::make_query_text(std::string(sql_str))));

        LOG_INFO("writing sql uid: {} upstream_traffic: {}, downstream_traffic: {} src: {} dst: {}", uid, upstream_size, downstream_size, src, dst)

        boost::asio::spawn(*io, [io, record_query, uid] (boost::asio::yield_context yield) {

            ozo::rows_of<std::int64_t> rows;

            // Connection info with host and port to coonect to
            auto conn_info = ozo::make_connection_info(sql_host);

            const auto connector = ozo::make_connector(conn_info, *io, ConnectorTimeout);
            ozo::result result;
            ozo::error_code ec;

            ozo::request(connector, record_query, WriteTimeout, std::ref(result), yield[ec]);

            if (ec) {
                LOG_INFO("uid: {} write sql err --> {}", uid, ec.message())
                return;
            }

        });

    }

};
#endif


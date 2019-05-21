#pragma once
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <iostream>
enum class TrafficType {
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
            case TrafficType::TCP:
            {
                return "TCP";
            }
            case TrafficType::UDP:
            {
                return "UDP";
            }
            case TrafficType::RAW:
            {
                return "RAW";
            }
        }

        throw std::runtime_error("unknow traffic type");
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

        auto record_query = ozo::make_query_builder(boost::hana::make_tuple(ozo::make_query_text(std::string(sql_str))));

        LOG_INFO("writing sql uid: {} upstream_traffic: {}, downstream_traffic: {} src: {} dst: {}", uid, upstream_size, downstream_size, src, dst)

        auto conn_info = ozo::make_connection_info(sql_host);

        ozo::rows_of<std::int64_t> rows;

        ozo::request(ozo::make_connector(conn_info, *io), record_query, ozo::into(rows),
                     [&](ozo::error_code ec, auto conn) {
                         if (ec) {
                             // Here we got an error, so we can get:
                             //           error code's message
                             std::cout << ec.message()
                                       //           error message from underlying libpq
                                       << " | " << error_message(conn)
                                       //           and error context from OZO
                                       << " | " << get_error_context(conn);
                             return;
                         };

                         // Connection must be in good state here,
                         // typically you do not need to check it manually
                         assert(ozo::connection_good(conn));
                         ozo::close_connection(conn);
//                         // We got results, let's handle, e.g. print it out
//                         std::cout << "id" << '\t' << "name" << std::endl;
//                         for(auto& row: rows) {
//                             std::cout << std::get<0>(row) << std::endl;
//                         }
                     });


//        boost::asio::spawn(*io, [io, record_query, uid] (boost::asio::yield_context yield) {
//
//
//            // Connection info with host and port to coonect to
//
//            const auto connector = ozo::make_connector(conn_info, *io, ConnectorTimeout);
//            ozo::result result;
//            ozo::error_code ec;
//
//            ozo::request(connector, record_query, WriteTimeout, std::ref(result), yield[ec]);
//
//            if (ec) {
//                LOG_INFO("uid: {} write sql err --> {}", uid, ec.message())
//                return;
//            }
//
//        });

    }

};
#endif


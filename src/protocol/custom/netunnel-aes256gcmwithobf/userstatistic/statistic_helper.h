#pragma once
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <ozo/request.h>
#include <ozo/connection_info.h>
#include <ozo/shortcuts.h>
#include "../../../../utils/logger.h"


const std::chrono::milliseconds ConnectorTimeout(500);
const std::chrono::milliseconds WriteTimeout(500);

// dump statistic when session is closing
class StatisticHelper{

public:


    static void DumpTrafficIntoSql(boost::asio::io_context* io, uint32_t uid, std::string ip, size_t upstream_size, size_t downstream_size)
    {

        if (!io) return;

        if (upstream_size == 0 || downstream_size == 0) return;

        using namespace ozo::literals;

        const auto query = "UPDATE user_statistic SET upstream_traffic = upstream_traffic+ "_SQL + std::int64_t(upstream_size) + ", downstream_size = downstream_size+"_SQL + std::int64_t(upstream_size) + " WHERE uid ="_SQL + std::int64_t(uid);
        LOG_INFO("writing sql uid: {} ip: {} upstream_traffic: {}, downstream_traffic: {}", uid, ip, upstream_size, downstream_size)

        boost::asio::spawn(*io, [io, query] (boost::asio::yield_context yield) {

            ozo::rows_of<std::int64_t> rows;

            // Connection info with host and port to coonect to
            auto conn_info = ozo::make_connection_info("host=127.0.0.1 port=5432");

            const auto connector = ozo::make_connector(conn_info, *io, ConnectorTimeout);
            ozo::result result;
            ozo::error_code ec;

            ozo::request(connector, query, WriteTimeout, std::ref(result), yield[ec]);

            if (ec) {
                LOG_INFO("write sql err --> {}", ec.message())
                return;
            }

        });


    }

};

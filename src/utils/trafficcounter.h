#pragma once
#include <cstdint>
#include <time.h>

class TrafficCounter
{
public:
	TrafficCounter();
	~TrafficCounter();

	static TrafficCounter* GetInstance()
	{
		static TrafficCounter* instance = new TrafficCounter();
		return instance;
	}

	inline void AddUpstreamTraffic(uint64_t size)
	{
		upstream_bytes += size;
	}

	inline void AddDownstreamTraffic(uint64_t size)
	{
		downstream_bytes += size;
	}


	uint64_t GetUpstreamBytes()
	{
		return upstream_bytes;
	}

	uint64_t GetDownstreamBytes()
	{
		return downstream_bytes;
	}

	inline void Reset()
	{
		upstream_bytes = downstream_bytes = 0;
	}

private:
	// unit byte
	uint64_t upstream_bytes = 0;
	uint64_t downstream_bytes = 0;

};


#define ENABLE_TRAFFIC_COUNT

#ifdef ENABLE_TRAFFIC_COUNT
#define AddUpTraffic(x) TrafficCounter::GetInstance()->AddUpstreamTraffic(x);
#define AddDownTraffic(x) TrafficCounter::GetInstance()->AddDownstreamTraffic(x);
#else
#define AddUpTraffic(x) 
#define AddDownTraffic(x) 
#endif
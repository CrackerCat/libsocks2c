#pragma once
#include "../utils/singleton.h"
#include <optional>
#include <boost/unordered_map.hpp>


using GlobalStateMap = boost::unordered_map<std::string, std::optional<std::string>>;

class GlobalState : public Singleton<GlobalState>
{
public:


	bool SetKeyValue(std::string key, std::string value)
	{
		auto it = map_.find(key);
		if (it != map_.end()) return false;

		map_.insert({ key, value });

	}

	void SetKeyValueOverride(std::string key, std::string value)
	{
		map_.insert_or_assign(key, value);
	}

	std::optional<std::string> GetByKey(std::string key)
	{
		auto it = map_.find(key);
		if (it == map_.end()) return std::nullopt;

		return it->second;
	}


private:

	GlobalStateMap map_;

};
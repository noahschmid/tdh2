/**
 * Simple timer class to monitor encryption/decryption speed
 * 
 * (C) 2021 Noah Schmid 
 */

#include <iostream>
#include <chrono>
#include <ctime>
#include <cmath>
#include <string>
#include <cmath>

class Timer {
public:
	Timer() {}
	void start(std::string label) {
		m_label = label;
		m_startTime = std::chrono::steady_clock::now();
	}

	void start() {
		m_label = "";
		m_startTime = std::chrono::steady_clock::now();
	}

	void stop() {
		m_endTime = std::chrono::steady_clock::now();
		printf("%s: %dms. \n", m_label.c_str(), (int)(std::chrono::duration_cast<std::chrono::milliseconds>(m_endTime - m_startTime).count()));
	}

	float getSecondsElapsed() {
		return (float)(std::chrono::duration_cast<std::chrono::seconds>(m_endTime - m_startTime).count());
	}

private:
	std::chrono::time_point<std::chrono::steady_clock> m_startTime;
	std::chrono::time_point<std::chrono::steady_clock> m_endTime;
	std::string m_label;
};
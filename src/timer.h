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
		m_startTime = std::chrono::system_clock::now();
	}

	void stop() {
		m_endTime = std::chrono::system_clock::now();
		printf("%s: %dms. \n\n", m_label.c_str(), std::chrono::duration_cast<std::chrono::milliseconds>(m_endTime - m_startTime).count());
	}

private:
	std::chrono::time_point<std::chrono::system_clock> m_startTime;
	std::chrono::time_point<std::chrono::system_clock> m_endTime;
	std::string m_label;
};
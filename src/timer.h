/**
 * (n+1)Sec Multiparty Off-the-Record Messaging library
 * Copyright (C) 2016, eQualit.ie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of version 3 of the GNU Lesser General
 * Public License as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef SRC_TIMER_H_
#define SRC_TIMER_H_

#include "interface.h"

#include <cassert>
#include <utility>

namespace np1sec
{

class Timer
{
	protected:
	class Body : public TimerCallback
	{
		public:
		void execute()
		{
			timer->m_body = nullptr;
			execute_payload();
			delete this;
		}
		
		virtual ~Body() {}
		virtual void execute_payload() = 0;
		TimerToken* token;
		Timer* timer;
	};
	
	public:
	Timer():
		m_body(nullptr)
	{}
	
	template<class Function>
	Timer(RoomInterface* interface, uint32_t timeout, Function function)
	{
		class Payload : public Body
		{
			protected:
			Function m_function;
			
			public:
			Payload(const Function& function):
				m_function(function)
			{}
			
			void execute_payload()
			{
				m_function();
			}
		};
		
		m_body = new Payload(function);
		m_body->timer = this;
		
		/*
		 * The timer might trigger during the set_timer call, which zeroes m_body and destroys the token.
		 */
		TimerToken* token = interface->set_timer(timeout, m_body);
		if (active()) {
			m_body->token = token;
		}
	}
	
	Timer(Timer&& other)
	{
		(*this) = std::move(other);
	}
	
	Timer& operator=(Timer&& other)
	{
		if (&other != this) {
			stop();
			m_body = other.m_body;
			if (m_body) {
				m_body->timer = this;
			}
			other.m_body = nullptr;
		}
		return *this;
	}
	
	~Timer()
	{
		stop();
	}
	
	void stop()
	{
		if (m_body) {
			assert(m_body->token);
			assert(m_body->timer);
			assert(m_body->timer == this);
			m_body->token->unset();
			delete m_body;
			m_body = nullptr;
		}
	}
	
	bool active() const
	{
		return m_body != nullptr;
	}
	
	protected:
	Body* m_body;
};

} // namespace np1sec

#endif

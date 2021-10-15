#pragma once
#include "thread.h"

#include <mini/function.h>

namespace mini::threading
{

	class thread_function
		: public thread
	{
			MINI_MAKE_NONCOPYABLE(thread_function);

		public:
			thread_function(
			    const function<void()>& functor
			)
				: _functor(functor)
			{
			}

			thread_function(
			    function<void()>&& functor
			)
				: _functor(std::move(functor))
			{
			}

		private:
			void
			thread_procedure(
			    void
			) override
			{
				_functor();
			}

			function<void()> _functor;
	};

}

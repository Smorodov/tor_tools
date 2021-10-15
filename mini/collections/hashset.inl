#include "hashset.h"

#include <mini/common.h>
#include <mini/memory.h>
#include <mini/algorithm.h>

namespace mini::collections {

//
// constructors.
//

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
hashset<T, IndexType, Hash, KeyEqual, Allocator>::hashset(
  void
  )
{

}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
hashset<T, IndexType, Hash, KeyEqual, Allocator>::hashset(
  const hashset& other
  )
  : _node_list(other._node_list)
  , _bucket_list(other._bucket_list)
{

}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
hashset<T, IndexType, Hash, KeyEqual, Allocator>::hashset(
  std::initializer_list<T> values
  )
{
  for (auto&& e : values)
  {
    insert(e);
  }
}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
hashset<T, IndexType, Hash, KeyEqual, Allocator>::hashset(
  hashset&& other
  )
{
  swap(other);
}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
hashset<T, IndexType, Hash, KeyEqual, Allocator>::hashset(
  size_type reserve_size
  )
{
  reserve(reserve_size);
}

//
// destructor.
//

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
hashset<T, IndexType, Hash, KeyEqual, Allocator>::~hashset(
  void
  )
{

}

//
// assign operators.
//

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
hashset<T, IndexType, Hash, KeyEqual, Allocator>&
hashset<T, IndexType, Hash, KeyEqual, Allocator>::operator=(
  const hashset& other
  )
{
  _node_list = other._node_list;
  _bucket_list = other._bucket_list;
}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
hashset<T, IndexType, Hash, KeyEqual, Allocator>&
hashset<T, IndexType, Hash, KeyEqual, Allocator>::operator=(
  hashset&& other
  )
{
  swap(other);

  return *this;
}

//
// swap.
//

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
void
hashset<T, IndexType, Hash, KeyEqual, Allocator>::swap(
  hashset& other
  )
{
  _node_list.swap(other._node_list);
  _bucket_list.swap(other._bucket_list);
}

//
// iterators.
//

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
typename hashset<T, IndexType, Hash, KeyEqual, Allocator>::iterator
hashset<T, IndexType, Hash, KeyEqual, Allocator>::begin(
  void
  )
{
  return iterator(_node_list.begin());
}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
typename hashset<T, IndexType, Hash, KeyEqual, Allocator>::const_iterator
hashset<T, IndexType, Hash, KeyEqual, Allocator>::begin(
  void
  ) const
{
  return const_iterator(_node_list.begin());
}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
typename hashset<T, IndexType, Hash, KeyEqual, Allocator>::iterator
hashset<T, IndexType, Hash, KeyEqual, Allocator>::end(
  void
  )
{
  return iterator(_node_list.end());
}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
typename hashset<T, IndexType, Hash, KeyEqual, Allocator>::const_iterator
hashset<T, IndexType, Hash, KeyEqual, Allocator>::end(
  void
  ) const
{
  return const_iterator(_node_list.end());
}

//
// capacity.
//

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
bool
hashset<T, IndexType, Hash, KeyEqual, Allocator>::is_empty(
  void
  ) const
{
  return _node_list.is_empty();
}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
typename hashset<T, IndexType, Hash, KeyEqual, Allocator>::size_type
hashset<T, IndexType, Hash, KeyEqual, Allocator>::get_size(
  void
  ) const
{
  return _node_list.get_size();
}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
typename hashset<T, IndexType, Hash, KeyEqual, Allocator>::size_type
hashset<T, IndexType, Hash, KeyEqual, Allocator>::get_bucket_count(
  void
  )
{
  return _bucket_list.get_size();
}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
void
hashset<T, IndexType, Hash, KeyEqual, Allocator>::reserve(
  size_type new_capacity
  )
{
  _node_list.reserve(new_capacity);
  _bucket_list.reserve(algorithm::nearest_power_of_2(new_capacity));
}

//
// lookup.
//

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
bool
hashset<T, IndexType, Hash, KeyEqual, Allocator>::contains(
  const T& item
  ) const
{
  return find(item) != end();
}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
typename hashset<T, IndexType, Hash, KeyEqual, Allocator>::iterator
hashset<T, IndexType, Hash, KeyEqual, Allocator>::find(
  const T& item
  )
{
  return find_generic(item);
}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
typename hashset<T, IndexType, Hash, KeyEqual, Allocator>::const_iterator
hashset<T, IndexType, Hash, KeyEqual, Allocator>::find(
  const T& item
  ) const
{
  return find_generic(item);
}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
typename hashset<T, IndexType, Hash, KeyEqual, Allocator>::index_type
hashset<T, IndexType, Hash, KeyEqual, Allocator>::get_bucket(
  const T& item
  ) const
{
  return get_bucket_generic(item);
}

//
// modifiers.
//

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
typename hashset<T, IndexType, Hash, KeyEqual, Allocator>::iterator
hashset<T, IndexType, Hash, KeyEqual, Allocator>::insert(
  const T& item
  )
{
  if (!_bucket_list.get_size())
  {
    _node_list.add({ item, invalid_index });

    _bucket_list.reserve(8);
    _bucket_list.add(0);
    return begin();
  }

  auto bucket = get_bucket(item);

  auto index = _bucket_list[bucket];
  while (index >= 0)
  {
    auto& node = _node_list[index];
    if (_equal(node.item, item))
    {
      node.item = item;
      return iterator(&_node_list[index]);
    }

    index = node.next;
  }

  index = static_cast<index_type>(_node_list.get_size());
  _node_list.add({ item, _bucket_list[bucket] });
  _bucket_list[bucket] = index;

  if (_node_list.get_size() > _bucket_list.get_size())
  {
    _bucket_list.resize(_bucket_list.get_size() * 2);
    rehash();
  }

  return iterator(&_node_list[index]);
}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
typename hashset<T, IndexType, Hash, KeyEqual, Allocator>::iterator
hashset<T, IndexType, Hash, KeyEqual, Allocator>::insert(
  T&& item
  )
{
  if (!_bucket_list.get_size())
  {
    _node_list.add({ std::move(item), invalid_index });

    _bucket_list.reserve(8);
    _bucket_list.add(0);
    return begin();
  }

  auto bucket = get_bucket(item);

  auto index = _bucket_list[bucket];
  while (index >= 0)
  {
    auto& node = _node_list[index];
    if (_equal(node.item, item))
    {
      node.item = std::move(item);
      return iterator(&_node_list[index]);
    }

    index = node.next;
  }

  index = static_cast<index_type>(_node_list.get_size());
  _node_list.add({ std::move(item), _bucket_list[bucket] });
  _bucket_list[bucket] = index;

  if (_node_list.get_size() > _bucket_list.get_size())
  {
    _bucket_list.resize(_bucket_list.get_size() * 2);
    rehash();
  }

  return iterator(&_node_list[index]);
}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
typename hashset<T, IndexType, Hash, KeyEqual, Allocator>::iterator
hashset<T, IndexType, Hash, KeyEqual, Allocator>::insert_many(
  std::initializer_list<T> values
  )
{
  auto it = end();
  for (auto&& e : values)
  {
    it = insert(e);
  }

  return it;
}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
typename hashset<T, IndexType, Hash, KeyEqual, Allocator>::iterator
hashset<T, IndexType, Hash, KeyEqual, Allocator>::remove(
  iterator it
  )
{
  mini_assert(it != end());

  auto bucket = get_bucket(*it);
  auto index = static_cast<index_type>(it._node - _node_list.get_buffer());

  unbind_entry(bucket, index);

  auto last = static_cast<index_type>(_node_list.get_size() - 1);
  if (index == last)
  {
    _node_list.pop();
    return end();
  }

  bucket = get_bucket(_node_list[last].item);
  unbind_entry(bucket, last);
  _node_list.remove_by_swap_at(index);

  auto& node = _node_list[index];
  mini_assert(bucket == get_bucket(node.item));

  node.next = _bucket_list[bucket];
  _bucket_list[bucket] = index;
  return it;
}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
void
hashset<T, IndexType, Hash, KeyEqual, Allocator>::remove(
  const value_type& item
  )
{
  auto it = find(item);

  if (it != end())
  {
    remove(it);
  }
}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
void
hashset<T, IndexType, Hash, KeyEqual, Allocator>::clear(
  void
  )
{
  _node_list.clear();
  _bucket_list.clear();
}

//
// protected methods.
//

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
template <
  typename U
>
typename hashset<T, IndexType, Hash, KeyEqual, Allocator>::iterator
hashset<T, IndexType, Hash, KeyEqual, Allocator>::find_generic(
  const U& item
  )
{
  if (is_empty())
  {
    return end();
  }

  auto index = _bucket_list[get_bucket_generic(item)];

  while (index >= 0)
  {
    auto& node = _node_list[index];

    if (_equal(node.item, item))
    {
      return iterator(&node);
    }

    index = node.next;
  }

  return end();
}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
template <
  typename U
>
typename hashset<T, IndexType, Hash, KeyEqual, Allocator>::const_iterator
hashset<T, IndexType, Hash, KeyEqual, Allocator>::find_generic(
  const U& item
  ) const
{
  if (is_empty())
  {
    return end();
  }

  auto index = _bucket_list[get_bucket_generic(item)];

  while (index >= 0)
  {
    auto& node = _node_list[index];

    if (_equal(node.item, item))
    {
      return const_iterator(&node);
    }

    index = node.next;
  }

  return end();
}

//
// private methods.
//

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
template <
  typename U
>
typename hashset<T, IndexType, Hash, KeyEqual, Allocator>::index_type
hashset<T, IndexType, Hash, KeyEqual, Allocator>::get_bucket_generic(
  const U& item
  ) const
{
  return static_cast<index_type>(
    _hasher(item) & (_bucket_list.get_size() - 1)
    );
}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
void
hashset<T, IndexType, Hash, KeyEqual, Allocator>::rehash(
  void
  )
{
  std::fill(_bucket_list.begin(), _bucket_list.end(), invalid_index);

  index_type index = 0;
  for (auto& node : _node_list)
  {
    auto bucket = get_bucket(node.item);

    node.next = _bucket_list[bucket];
    _bucket_list[bucket] = index;

    ++index;
  }
}

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
void
hashset<T, IndexType, Hash, KeyEqual, Allocator>::unbind_entry(
  size_type bucket,
  index_type index
  )
{
  auto tmp = _bucket_list[bucket];
  auto prev = invalid_index;

  while (tmp != invalid_index)
  {
    if (tmp == index)
    {
      break;
    }

    auto& node = _node_list[tmp];
    prev = tmp;
    tmp = node.next;
  }

  mini_assert(tmp != invalid_index);
  auto next = _node_list[index].next;

  if (prev != invalid_index)
  {
    _node_list[prev].next = next;
  }
  else
  {
    //
    // replace head.
    //

    mini_assert(_bucket_list[bucket] == index);
    _bucket_list[bucket] = next;
  }
}

}

namespace mini {

template <
  typename T,
  typename IndexType,
  typename Hash,
  typename KeyEqual,
  typename Allocator
>
void
swap(
  mini::collections::hashset<T, IndexType, Hash, KeyEqual, Allocator>& lhs,
  mini::collections::hashset<T, IndexType, Hash, KeyEqual, Allocator>& rhs
  )
{
  lhs.swap(rhs);
}

}

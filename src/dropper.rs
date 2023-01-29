use core::mem::ManuallyDrop;

pub struct FnDropper<V, F: FnMut(V)> {
	v: Option<V>,
	f: F,
}

impl<V, F: FnMut(V)> FnDropper<V, F> {
	pub fn new(v: V, f: F) -> Self {
		// Safety: It is impossible to construct using a `None`
		Self { v: Some(v), f }
	}

	pub fn disarm(self) -> V {
		// Safety: After extracting `v`, `self` is never dropped
		let mut s = ManuallyDrop::new(self);
		// Safety: `disarm` can only be called once
		s.v.take().unwrap()
	}
}

impl<V, F: FnMut(V)> Drop for FnDropper<V, F> {
	fn drop(&mut self) {
		// Safety: `drop` should not be called if `v` is `None`.
		(self.f)(self.v.take().unwrap());
	}
}

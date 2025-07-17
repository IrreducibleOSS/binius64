// Copyright 2025 Irreducible Inc.

#[derive(thiserror::Error, Debug)]
pub enum Error {
	#[error("layers empty")]
	LayersEmpty,
	#[error("last layer empty")]
	LastLayerEmpty,
}

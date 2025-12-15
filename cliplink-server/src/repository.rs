use std::{collections::HashMap, sync::LazyLock};

pub trait Repository<T, E> {
    fn get(&self, id: &String, clip: Option<&String>) -> Result<&T, E>;
    fn patch(&mut self, id: &String, clip: Option<&String>, payload: T) -> Result<(), E>;
}

#[derive(Debug, thiserror::Error)]
pub enum InMemoryRepositoryError {
    #[error("not found")]
    NotFound,
}

#[derive(Default)]
pub struct InMemoryRepository<T>(HashMap<String, HashMap<String, T>>);

impl<T> InMemoryRepository<T> {
    const DEFAULT_CLIP: LazyLock<String> = LazyLock::new(|| String::from("default"));
}

impl<T> Repository<T, InMemoryRepositoryError> for InMemoryRepository<T>
where
    T: Into<Vec<u8>>,
{
    fn get(&self, id: &String, clip: Option<&String>) -> Result<&T, InMemoryRepositoryError> {
        println!("get id: {id}, clip: {clip:?}");
        self.0
            .get(id)
            .map(|item| item.get(clip.unwrap_or(&*Self::DEFAULT_CLIP)))
            .ok_or(InMemoryRepositoryError::NotFound)?
            .ok_or(InMemoryRepositoryError::NotFound)
    }

    fn patch(
        &mut self,
        id: &String,
        clip: Option<&String>,
        payload: T,
    ) -> Result<(), InMemoryRepositoryError> {
        println!("patch id: {id}, clip: {clip:?}");
        let clip_store = match self.0.get_mut(id) {
            Some(store) => store,
            None => {
                self.0.insert(id.clone(), HashMap::new());
                self.0.get_mut(id).unwrap()
            }
        };

        clip_store.insert(clip.unwrap_or(&*Self::DEFAULT_CLIP).clone(), payload);

        Ok(())
    }
}

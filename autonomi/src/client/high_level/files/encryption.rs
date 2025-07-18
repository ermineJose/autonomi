// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Metadata, FILE_ENCRYPT_BATCH_SIZE};

use crate::client::{data_types::chunk::DataMapChunk, utils::process_tasks_with_max_concurrency};
use crate::data::DataAddress;
use crate::files::get_relative_file_path_from_abs_file_and_folder_path;
use crate::self_encryption::encrypt;
use crate::Client;
use ant_protocol::storage::Chunk;
use bytes::Bytes;
use std::path::PathBuf;
use std::time::Instant;

impl Client {
    /// Encrypts all files in a directory and returns the encryption results (common logic)
    async fn encrypt_directory_files(
        &self,
        dir_path: PathBuf,
    ) -> Result<Vec<Result<(String, Vec<Chunk>, Chunk, PathBuf, Metadata), String>>, walkdir::Error>
    {
        let mut encryption_tasks = vec![];

        for entry in walkdir::WalkDir::new(&dir_path) {
            let entry = entry?;

            if entry.file_type().is_dir() {
                continue;
            }

            let dir_path = dir_path.clone();

            encryption_tasks.push(async move {
                let file_path = entry.path().to_path_buf();

                info!("Encrypting file: {file_path:?}..");
                #[cfg(feature = "loud")]
                println!("Encrypting file: {file_path:?}..");

                let data = tokio::fs::read(&file_path)
                    .await
                    .map_err(|err| format!("Could not read file {file_path:?}: {err:?}"))?;
                let data = Bytes::from(data);

                if data.len() < 3 {
                    let err_msg =
                        format!("Skipping file {file_path:?}, as it is smaller than 3 bytes");
                    return Err(err_msg);
                }

                let now = Instant::now();

                let (data_map_chunk, chunks) = encrypt(data).map_err(|err| err.to_string())?;

                debug!("Encryption of {file_path:?} took: {:.2?}", now.elapsed());

                let metadata = super::fs_public::metadata_from_entry(&entry);
                let relative_path =
                    get_relative_file_path_from_abs_file_and_folder_path(&file_path, &dir_path);

                Ok((
                    file_path.to_string_lossy().to_string(),
                    chunks,
                    data_map_chunk,
                    relative_path,
                    metadata,
                ))
            });
        }

        let encryption_results =
            process_tasks_with_max_concurrency(encryption_tasks, *FILE_ENCRYPT_BATCH_SIZE).await;

        Ok(encryption_results)
    }

    /// Encrypts all files in a directory and returns the encryption results for private files
    pub(crate) async fn encrypt_directory_files_private(
        &self,
        dir_path: PathBuf,
    ) -> Result<
        Vec<Result<(String, Vec<Chunk>, (PathBuf, DataMapChunk, Metadata)), String>>,
        walkdir::Error,
    > {
        let results = self.encrypt_directory_files(dir_path).await?;
        Ok(results
            .into_iter()
            .map(|res| {
                res.map(
                    |(file_path, chunks, data_map_chunk, relative_path, metadata)| {
                        (
                            file_path,
                            chunks,
                            (relative_path, DataMapChunk::from(data_map_chunk), metadata),
                        )
                    },
                )
            })
            .collect())
    }

    /// Encrypts all files in a directory and returns the encryption results for public files
    pub(crate) async fn encrypt_directory_files_public(
        &self,
        dir_path: PathBuf,
    ) -> Result<
        Vec<Result<(String, Vec<Chunk>, (PathBuf, DataAddress, Metadata)), String>>,
        walkdir::Error,
    > {
        let results = self.encrypt_directory_files(dir_path).await?;
        Ok(results
            .into_iter()
            .map(|res| {
                res.map(
                    |(file_path, mut chunks, data_map_chunk, relative_path, metadata)| {
                        let data_address = *data_map_chunk.name();
                        chunks.push(data_map_chunk);
                        (
                            file_path,
                            chunks,
                            (relative_path, DataAddress::new(data_address), metadata),
                        )
                    },
                )
            })
            .collect())
    }
}

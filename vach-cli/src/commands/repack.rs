use super::CommandTrait;

pub struct Evaluator;

impl CommandTrait for  Evaluator {
    fn evaluate(&self, _: &clap::ArgMatches) -> anyhow::Result<()> {
        todo!()
    }

    fn version(&self) -> &'static str {
        todo!()
    }
}
